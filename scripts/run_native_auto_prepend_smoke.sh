#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXT_PATH="${ROOT_DIR}/ext/xmark/modules/xmark.so"
PREPEND_PATH="${ROOT_DIR}/scripts/auto_prepend.php"
APP_DOCROOT="${ROOT_DIR}/tests/fixtures/unmodified_app/public"
EXTRA_PHP_ARGS_RAW="${PHP_TAINT_TRACE_SMOKE_EXTRA_PHP_ARGS:-}"
EMIT_CANDIDATES="${PHP_TAINT_TRACE_EMIT_CANDIDATES:-0}"
EXTRA_PHP_ARGS=()

if [[ -n "${EXTRA_PHP_ARGS_RAW}" ]]; then
  # shellcheck disable=SC2206
  EXTRA_PHP_ARGS=(${EXTRA_PHP_ARGS_RAW})
fi

if [[ ! -f "${EXT_PATH}" ]]; then
  echo "Missing extension at ${EXT_PATH}. Build first with ./scripts/build_xmark_extension.sh" >&2
  exit 1
fi

if [[ ! -f "${PREPEND_PATH}" ]]; then
  echo "Missing auto-prepend script at ${PREPEND_PATH}" >&2
  exit 1
fi

if [[ ! -d "${APP_DOCROOT}" ]]; then
  echo "Missing smoke app docroot at ${APP_DOCROOT}" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d)"
FINDINGS_PATH="${TMP_DIR}/findings.jsonl"
SERVER_LOG="${TMP_DIR}/server.log"
PORT="$(php -r '
$server = @stream_socket_server("tcp://127.0.0.1:0", $errno, $errstr);
if ($server === false) {
    fwrite(STDERR, "failed to allocate ephemeral port: " . $errstr . PHP_EOL);
    exit(1);
}
$name = stream_socket_get_name($server, false);
fclose($server);
if (!is_string($name) || !str_contains($name, ":")) {
    fwrite(STDERR, "failed to resolve ephemeral port" . PHP_EOL);
    exit(1);
}
echo substr($name, strrpos($name, ":") + 1);
')"

SERVER_PID=0
cleanup() {
  if [[ ${SERVER_PID} -gt 0 ]] && kill -0 "${SERVER_PID}" >/dev/null 2>&1; then
    kill "${SERVER_PID}" >/dev/null 2>&1 || true
    wait "${SERVER_PID}" >/dev/null 2>&1 || true
  fi
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

(
  export PHP_TAINT_TRACE_ENABLED=1
  export PHP_TAINT_TRACE_FINDINGS_FILE="${FINDINGS_PATH}"
  export PHP_TAINT_TRACE_ERROR_LOG=0
  export PHP_TAINT_TRACE_CLEAR_AFTER_FLUSH=1
  export PHP_TAINT_TRACE_EMIT_CANDIDATES="${EMIT_CANDIDATES}"
  export PHP_TAINT_TRACE_ENABLE_OPCODE_HOOKS="${PHP_TAINT_TRACE_ENABLE_OPCODE_HOOKS:-0}"
  exec php -n \
    -d "extension=${EXT_PATH}" \
    "${EXTRA_PHP_ARGS[@]}" \
    -d "auto_prepend_file=${PREPEND_PATH}" \
    -S "127.0.0.1:${PORT}" \
    -t "${APP_DOCROOT}"
) >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!

READY=0
for _ in $(seq 1 50); do
  if php -r '
$fp = @fsockopen("127.0.0.1", (int) $argv[1], $errno, $errstr, 0.1);
if ($fp !== false) {
    fclose($fp);
    exit(0);
}
exit(1);
' "${PORT}"; then
    READY=1
    break
  fi
  sleep 0.1
done

if [[ ${READY} -ne 1 ]]; then
  echo "Built-in PHP server failed to start on 127.0.0.1:${PORT}" >&2
  echo "--- server log ---" >&2
  cat "${SERVER_LOG}" >&2 || true
  exit 1
fi

php -r '
$url = $argv[1];
$body = @file_get_contents($url);
if (!is_string($body)) {
    fwrite(STDERR, "failed request to " . $url . PHP_EOL);
    exit(1);
}
' "http://127.0.0.1:${PORT}/?name=xtanzi"

FOUND=0
for _ in $(seq 1 20); do
  if [[ -s "${FINDINGS_PATH}" ]]; then
    if php -r '
$path = $argv[1];
$lines = @file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
if (!is_array($lines)) {
    exit(1);
}
foreach ($lines as $line) {
    $payload = json_decode($line, true);
    if (!is_array($payload)) {
        continue;
    }
    $findings = $payload["findings"] ?? array();
    if (!is_array($findings)) {
        continue;
    }
    foreach ($findings as $finding) {
        if (!is_array($finding)) {
            continue;
        }
        if (($finding["sink_name"] ?? null) === "printf" && ($finding["sink_category"] ?? null) === "xss") {
            exit(0);
        }
    }
}
exit(2);
' "${FINDINGS_PATH}"; then
      FOUND=1
      break
    fi
  fi
  sleep 0.1
done

if [[ ${FOUND} -ne 1 ]]; then
  echo "Smoke check failed: no printf/xss finding in ${FINDINGS_PATH}" >&2
  if [[ -f "${FINDINGS_PATH}" ]]; then
    echo "--- findings ---" >&2
    cat "${FINDINGS_PATH}" >&2 || true
  fi
  echo "--- server log ---" >&2
  cat "${SERVER_LOG}" >&2 || true
  exit 1
fi

if [[ "${EMIT_CANDIDATES}" == "1" ]]; then
  if ! php -r '
$path = $argv[1];
$lines = @file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
if (!is_array($lines)) {
    exit(1);
}
foreach ($lines as $line) {
    $payload = json_decode($line, true);
    if (!is_array($payload)) {
        continue;
    }
    $candidates = $payload["candidates"] ?? null;
    if (!is_array($candidates)) {
        continue;
    }
    foreach ($candidates as $candidate) {
        if (!is_array($candidate)) {
            continue;
        }
        if (($candidate["sink_name"] ?? null) === "printf" && ($candidate["sink_category"] ?? null) === "xss") {
            exit(0);
        }
    }
}
exit(2);
' "${FINDINGS_PATH}"; then
    echo "Smoke check failed: candidate emission enabled but no printf/xss candidate in ${FINDINGS_PATH}" >&2
    if [[ -f "${FINDINGS_PATH}" ]]; then
      echo "--- findings ---" >&2
      cat "${FINDINGS_PATH}" >&2 || true
    fi
    echo "--- server log ---" >&2
    cat "${SERVER_LOG}" >&2 || true
    exit 1
  fi
else
  if ! php -r '
$path = $argv[1];
$lines = @file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
if (!is_array($lines)) {
    exit(1);
}
foreach ($lines as $line) {
    $payload = json_decode($line, true);
    if (!is_array($payload)) {
        continue;
    }
    if (array_key_exists("candidates", $payload)) {
        exit(3);
    }
}
exit(0);
' "${FINDINGS_PATH}"; then
    echo "Smoke check failed: candidates field present while candidate emission is disabled." >&2
    if [[ -f "${FINDINGS_PATH}" ]]; then
      echo "--- findings ---" >&2
      cat "${FINDINGS_PATH}" >&2 || true
    fi
    echo "--- server log ---" >&2
    cat "${SERVER_LOG}" >&2 || true
    exit 1
  fi
fi

echo "Native auto-prepend smoke passed."
