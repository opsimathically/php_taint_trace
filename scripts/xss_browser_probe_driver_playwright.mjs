#!/usr/bin/env node

const args = process.argv.slice(2);

function parseArgs(rawArgs) {
  const parsed = {};
  for (let i = 0; i < rawArgs.length; i += 1) {
    const key = rawArgs[i];
    const next = rawArgs[i + 1];
    if (!key.startsWith("--")) {
      continue;
    }

    if (typeof next === "undefined" || next.startsWith("--")) {
      parsed[key.slice(2)] = "1";
      continue;
    }

    parsed[key.slice(2)] = next;
    i += 1;
  }
  return parsed;
}

const parsed = parseArgs(args);
const url = String(parsed.url || "");
const nonce = String(parsed.nonce || "");
const timeoutMs = Number.parseInt(String(parsed["timeout-ms"] || parsed.timeout_ms || "8000"), 10) || 8000;

const output = {
  success: false,
  executed: false,
  observed_nonce: null,
  final_url: null,
  status: null,
  console_logs: [],
  error: null,
};

if (url.trim() === "" || nonce.trim() === "") {
  output.error = "missing required --url/--nonce arguments";
  console.log(JSON.stringify(output));
  process.exit(2);
}

let browser = null;
let context = null;
try {
  const playwright = await import("playwright");
  browser = await playwright.chromium.launch({ headless: true });
  context = await browser.newContext({
    extraHTTPHeaders: {
      "X-Php-Taint-Trace-Replay": "1",
    },
  });
  const page = await context.newPage();

  page.on("console", (message) => {
    const text = message.text();
    output.console_logs.push(text.length > 400 ? `${text.slice(0, 400)}...` : text);
  });

  const response = await page.goto(url, {
    waitUntil: "domcontentloaded",
    timeout: timeoutMs,
  });

  await page.waitForTimeout(250);

  const executionProbe = await page.evaluate((expectedNonce) => {
    const windowNonce = typeof window !== "undefined" ? window.__ptt_xss_nonce : null;
    const attrNonce = document?.documentElement?.getAttribute("data-ptt-xss");
    const bodyAttrNonce = document?.body?.getAttribute("data-ptt-xss");
    const observedNonce = windowNonce || attrNonce || bodyAttrNonce || null;

    return {
      executed: observedNonce === expectedNonce,
      observedNonce,
    };
  }, nonce);

  output.success = true;
  output.executed = Boolean(executionProbe?.executed);
  output.observed_nonce =
    typeof executionProbe?.observedNonce === "string" ? executionProbe.observedNonce : null;
  output.final_url = page.url();
  output.status = response ? response.status() : null;
} catch (error) {
  output.error = error instanceof Error ? error.message : String(error);
} finally {
  if (context) {
    await context.close();
  }
  if (browser) {
    await browser.close();
  }
}

console.log(JSON.stringify(output));
process.exit(output.success ? 0 : 2);
