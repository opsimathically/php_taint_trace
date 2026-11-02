#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_PATH="${PHP_TAINT_TRACE_TEST_CONFIG:-${XDG_CONFIG_HOME:-${HOME}/.config}/php_taint_trace/testing_container_config.json}"
HOST_LABEL="${PHP_TAINT_TRACE_TEST_HOST_LABEL:-lab.example.invalid}"
REMOTE_ROOT="/opt/php_taint_trace_vuln_lab"
EXTENSION_PROFILE="${PHP_TAINT_TRACE_REMOTE_EXTENSION_PROFILE:-base}"
STRICT_EXTENSION_PROFILE=0
XSS_BROWSER_MODE="${PHP_TAINT_TRACE_REMOTE_XSS_BROWSER_MODE:-off}"
XSS_BROWSER_DRIVER_CMD="${PHP_TAINT_TRACE_REMOTE_XSS_BROWSER_DRIVER_CMD:-}"
XSS_BROWSER_TIMEOUT_MS="${PHP_TAINT_TRACE_REMOTE_XSS_BROWSER_TIMEOUT_MS:-8000}"
VALIDATE_XSS_BROWSER_REASON="${PHP_TAINT_TRACE_REMOTE_VALIDATE_XSS_BROWSER_REASON:-}"
VALIDATE_XSS_BROWSER_REASON_SET=0
VALIDATE_XSS_BROWSER_EXECUTION_CONFIRMED="${PHP_TAINT_TRACE_REMOTE_VALIDATE_XSS_BROWSER_EXECUTION_CONFIRMED:-}"
VALIDATE_XSS_BROWSER_EXECUTION_CONFIRMED_SET=0
REQUIRE_XSS_BROWSER_READINESS="${PHP_TAINT_TRACE_REMOTE_REQUIRE_XSS_BROWSER_READINESS:-}"
REQUIRE_XSS_BROWSER_READINESS_SET=0
XSS_BROWSER_ADVISORY_MAX_FAILURE_RATE="${PHP_TAINT_TRACE_REMOTE_XSS_BROWSER_ADVISORY_MAX_FAILURE_RATE:-}"
XSS_BROWSER_ADVISORY_MAX_UNCONFIGURED_RATE="${PHP_TAINT_TRACE_REMOTE_XSS_BROWSER_ADVISORY_MAX_UNCONFIGURED_RATE:-}"
MAX_DEAD_LETTERS="${PHP_TAINT_TRACE_REMOTE_MAX_DEAD_LETTERS:-0}"
VERIFIER_BACKEND="${PHP_TAINT_TRACE_REMOTE_VERIFIER_BACKEND:-php_worker}"
VERIFIER_STABILITY_ROUNDS="${PHP_TAINT_TRACE_REMOTE_VERIFIER_STABILITY_ROUNDS:-2}"

usage() {
  cat <<'USAGE'
Usage: scripts/run_remote_verifier_tests.sh [--config PATH] [--host-label LABEL] [--remote-root PATH]
                                          [--extension-profile base|extended_sql|extended_rce|extended_all]
                                          [--strict-extension-profile]
                                          [--xss-browser-mode off|advisory|enforce]
                                          [--xss-browser-driver-cmd "CMD WITH {url}/{nonce}/{timeout_ms}"]
                                          [--xss-browser-timeout-ms N]
                                          [--validate-xss-browser-reason 0|1]
                                          [--validate-xss-browser-execution-confirmed 0|1]
                                          [--require-xss-browser-readiness 0|1]
                                          [--xss-browser-advisory-max-failure-rate 0.0-1.0]
                                          [--xss-browser-advisory-max-unconfigured-rate 0.0-1.0]
                                          [--max-dead-letters N]
                                          [--verifier-backend php_worker]
                                          [--verifier-stability-rounds N]

Runs opt-in remote verifier end-to-end checks across all verifier classes.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)
      CONFIG_PATH="$2"
      shift 2
      ;;
    --host-label)
      HOST_LABEL="$2"
      shift 2
      ;;
    --remote-root)
      REMOTE_ROOT="$2"
      shift 2
      ;;
    --extension-profile)
      EXTENSION_PROFILE="$2"
      shift 2
      ;;
    --strict-extension-profile)
      STRICT_EXTENSION_PROFILE=1
      shift 1
      ;;
    --xss-browser-mode)
      XSS_BROWSER_MODE="$2"
      shift 2
      ;;
    --xss-browser-driver-cmd)
      XSS_BROWSER_DRIVER_CMD="$2"
      shift 2
      ;;
    --xss-browser-timeout-ms)
      XSS_BROWSER_TIMEOUT_MS="$2"
      shift 2
      ;;
    --validate-xss-browser-reason)
      VALIDATE_XSS_BROWSER_REASON="$2"
      VALIDATE_XSS_BROWSER_REASON_SET=1
      shift 2
      ;;
    --validate-xss-browser-execution-confirmed)
      VALIDATE_XSS_BROWSER_EXECUTION_CONFIRMED="$2"
      VALIDATE_XSS_BROWSER_EXECUTION_CONFIRMED_SET=1
      shift 2
      ;;
    --require-xss-browser-readiness)
      REQUIRE_XSS_BROWSER_READINESS="$2"
      REQUIRE_XSS_BROWSER_READINESS_SET=1
      shift 2
      ;;
    --xss-browser-advisory-max-failure-rate)
      XSS_BROWSER_ADVISORY_MAX_FAILURE_RATE="$2"
      shift 2
      ;;
    --xss-browser-advisory-max-unconfigured-rate)
      XSS_BROWSER_ADVISORY_MAX_UNCONFIGURED_RATE="$2"
      shift 2
      ;;
    --max-dead-letters)
      MAX_DEAD_LETTERS="$2"
      shift 2
      ;;
    --verifier-backend)
      VERIFIER_BACKEND="$2"
      shift 2
      ;;
    --verifier-stability-rounds)
      VERIFIER_STABILITY_ROUNDS="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

EXTENSION_PROFILE="$(printf '%s' "${EXTENSION_PROFILE}" | tr '[:upper:]' '[:lower:]' | xargs)"
case "${EXTENSION_PROFILE}" in
  base|extended_sql|extended_rce|extended_all)
    ;;
  *)
    echo "Invalid --extension-profile: ${EXTENSION_PROFILE}. Expected base|extended_sql|extended_rce|extended_all." >&2
    exit 1
    ;;
esac

XSS_BROWSER_MODE="$(printf '%s' "${XSS_BROWSER_MODE}" | tr '[:upper:]' '[:lower:]' | xargs)"
case "${XSS_BROWSER_MODE}" in
  off|advisory|enforce)
    ;;
  *)
    echo "Invalid --xss-browser-mode: ${XSS_BROWSER_MODE}. Expected off|advisory|enforce." >&2
    exit 1
    ;;
esac

if ! [[ "${XSS_BROWSER_TIMEOUT_MS}" =~ ^[0-9]+$ ]] || [[ "${XSS_BROWSER_TIMEOUT_MS}" -le 0 ]]; then
  echo "Invalid --xss-browser-timeout-ms: ${XSS_BROWSER_TIMEOUT_MS}. Expected positive integer." >&2
  exit 1
fi

if [[ "${VALIDATE_XSS_BROWSER_REASON_SET}" -eq 0 ]]; then
  if [[ "${XSS_BROWSER_MODE}" == "off" ]]; then
    VALIDATE_XSS_BROWSER_REASON=0
  else
    VALIDATE_XSS_BROWSER_REASON=1
  fi
fi

if [[ "${VALIDATE_XSS_BROWSER_EXECUTION_CONFIRMED_SET}" -eq 0 ]]; then
  if [[ "${XSS_BROWSER_MODE}" == "enforce" ]]; then
    VALIDATE_XSS_BROWSER_EXECUTION_CONFIRMED=1
  else
    VALIDATE_XSS_BROWSER_EXECUTION_CONFIRMED=0
  fi
fi

if [[ "${REQUIRE_XSS_BROWSER_READINESS_SET}" -eq 0 ]]; then
  if [[ "${XSS_BROWSER_MODE}" == "off" ]]; then
    REQUIRE_XSS_BROWSER_READINESS=0
  else
    REQUIRE_XSS_BROWSER_READINESS=1
  fi
fi

if [[ -z "${XSS_BROWSER_ADVISORY_MAX_FAILURE_RATE}" ]]; then
  XSS_BROWSER_ADVISORY_MAX_FAILURE_RATE=0.25
fi
if [[ -z "${XSS_BROWSER_ADVISORY_MAX_UNCONFIGURED_RATE}" ]]; then
  XSS_BROWSER_ADVISORY_MAX_UNCONFIGURED_RATE=0.10
fi

normalize_bool() {
  local value="$1"
  value="$(printf '%s' "${value}" | tr '[:upper:]' '[:lower:]' | xargs)"
  case "${value}" in
    1|true|yes|on)
      echo 1
      ;;
    0|false|no|off|"")
      echo 0
      ;;
    *)
      return 1
      ;;
  esac
}

if ! VALIDATE_XSS_BROWSER_REASON="$(normalize_bool "${VALIDATE_XSS_BROWSER_REASON}")"; then
  echo "Invalid --validate-xss-browser-reason: ${VALIDATE_XSS_BROWSER_REASON}" >&2
  exit 1
fi
if ! VALIDATE_XSS_BROWSER_EXECUTION_CONFIRMED="$(normalize_bool "${VALIDATE_XSS_BROWSER_EXECUTION_CONFIRMED}")"; then
  echo "Invalid --validate-xss-browser-execution-confirmed: ${VALIDATE_XSS_BROWSER_EXECUTION_CONFIRMED}" >&2
  exit 1
fi
if ! REQUIRE_XSS_BROWSER_READINESS="$(normalize_bool "${REQUIRE_XSS_BROWSER_READINESS}")"; then
  echo "Invalid --require-xss-browser-readiness: ${REQUIRE_XSS_BROWSER_READINESS}" >&2
  exit 1
fi

for rate_value in "${XSS_BROWSER_ADVISORY_MAX_FAILURE_RATE}" "${XSS_BROWSER_ADVISORY_MAX_UNCONFIGURED_RATE}"; do
  if ! php -r '$raw = trim((string) ($argv[1] ?? "")); if ($raw === "" || !is_numeric($raw)) { exit(1); } $v = (float) $raw; if ($v < 0.0 || $v > 1.0) { exit(1); }' "${rate_value}"; then
    echo "Invalid advisory rate threshold: ${rate_value}. Expected numeric range [0.0, 1.0]." >&2
    exit 1
  fi
done

if ! [[ "${MAX_DEAD_LETTERS}" =~ ^[0-9]+$ ]]; then
  echo "Invalid --max-dead-letters: ${MAX_DEAD_LETTERS}. Expected non-negative integer." >&2
  exit 1
fi
if ! [[ "${VERIFIER_STABILITY_ROUNDS}" =~ ^[0-9]+$ ]] || [[ "${VERIFIER_STABILITY_ROUNDS}" -lt 1 ]]; then
  echo "Invalid --verifier-stability-rounds: ${VERIFIER_STABILITY_ROUNDS}. Expected positive integer." >&2
  exit 1
fi
VERIFIER_BACKEND="$(printf '%s' "${VERIFIER_BACKEND}" | tr '[:upper:]' '[:lower:]' | xargs)"
case "${VERIFIER_BACKEND}" in
  php_worker)
    ;;
  *)
    echo "Invalid --verifier-backend: ${VERIFIER_BACKEND}. This script now supports php_worker only." >&2
    exit 1
    ;;
esac

if [[ "${XSS_BROWSER_MODE}" != "off" && -z "${XSS_BROWSER_DRIVER_CMD}" ]]; then
  echo "[remote-verifier] Warning: browser mode '${XSS_BROWSER_MODE}' requested without --xss-browser-driver-cmd; browser probe runner will be unconfigured." >&2
fi

for cmd in python3 ssh setsid; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "Missing required local command: ${cmd}" >&2
    exit 1
  fi
done

if [[ ! -f "${CONFIG_PATH}" ]]; then
  echo "Config file not found: ${CONFIG_PATH}" >&2
  exit 1
fi

mapfile -t _cfg < <(python3 - "$CONFIG_PATH" "$HOST_LABEL" <<'PY'
import json
import sys
from pathlib import Path

cfg_path = Path(sys.argv[1])
label = sys.argv[2]
data = json.loads(cfg_path.read_text())
if label not in data:
    raise SystemExit(f"Host label not found in config: {label}")
entry = data[label]
required = ("ipv4", "ssh_username", "ssh_password")
missing = [k for k in required if k not in entry or not str(entry[k]).strip()]
if missing:
    raise SystemExit(f"Missing required config keys for {label}: {', '.join(missing)}")
print(entry["ipv4"])
print(entry["ssh_username"])
print(entry["ssh_password"])
PY
)

HOST="${_cfg[0]}"
SSH_USER="${_cfg[1]}"
SSH_PASSWORD="${_cfg[2]}"

ASKPASS_SCRIPT="$(mktemp /tmp/php_taint_trace_askpass.XXXXXX)"
cleanup() {
  rm -f "${ASKPASS_SCRIPT}"
}
trap cleanup EXIT

cat > "${ASKPASS_SCRIPT}" <<'ASKPASS'
#!/usr/bin/env sh
printf '%s\n' "$SSH_PASSWORD"
ASKPASS
chmod 700 "${ASKPASS_SCRIPT}"

SSH_OPTS=(
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o PubkeyAuthentication=no
  -o PreferredAuthentications=password
  -o NumberOfPasswordPrompts=1
  -o ConnectTimeout=15
)

ssh_exec() {
  DISPLAY=:0 \
  SSH_ASKPASS="${ASKPASS_SCRIPT}" \
  SSH_ASKPASS_REQUIRE=force \
  SSH_PASSWORD="${SSH_PASSWORD}" \
  setsid -w ssh "${SSH_OPTS[@]}" "${SSH_USER}@${HOST}" "$@"
}

REMOTE_PROJECT_ROOT="${REMOTE_ROOT}/rewrite"
REMOTE_VERIFIER_DIR="${REMOTE_PROJECT_ROOT}/.remote_vuln_lab_runtime/verifier"
REMOTE_CMD="$(printf \
  "REMOTE_PROJECT_ROOT=%q REMOTE_VERIFIER_DIR=%q EXTENSION_PROFILE=%q XSS_BROWSER_MODE=%q XSS_BROWSER_DRIVER_CMD=%q XSS_BROWSER_TIMEOUT_MS=%q VALIDATE_XSS_BROWSER_REASON=%q VALIDATE_XSS_BROWSER_EXECUTION_CONFIRMED=%q XSS_BROWSER_ADVISORY_MAX_FAILURE_RATE=%q XSS_BROWSER_ADVISORY_MAX_UNCONFIGURED_RATE=%q REQUIRE_XSS_BROWSER_READINESS=%q MAX_DEAD_LETTERS=%q VERIFIER_BACKEND=%q VERIFIER_STABILITY_ROUNDS=%q bash -s" \
  "${REMOTE_PROJECT_ROOT}" \
  "${REMOTE_VERIFIER_DIR}" \
  "${EXTENSION_PROFILE}" \
  "${XSS_BROWSER_MODE}" \
  "${XSS_BROWSER_DRIVER_CMD}" \
  "${XSS_BROWSER_TIMEOUT_MS}" \
  "${VALIDATE_XSS_BROWSER_REASON}" \
  "${VALIDATE_XSS_BROWSER_EXECUTION_CONFIRMED}" \
  "${XSS_BROWSER_ADVISORY_MAX_FAILURE_RATE}" \
  "${XSS_BROWSER_ADVISORY_MAX_UNCONFIGURED_RATE}" \
  "${REQUIRE_XSS_BROWSER_READINESS}" \
  "${MAX_DEAD_LETTERS}" \
  "${VERIFIER_BACKEND}" \
  "${VERIFIER_STABILITY_ROUNDS}" \
)"
REMOTE_VALIDATE_CMD=""

echo "[remote-verifier] Browser mode: ${XSS_BROWSER_MODE} (validate_signal=${VALIDATE_XSS_BROWSER_REASON} validate_execution=${VALIDATE_XSS_BROWSER_EXECUTION_CONFIRMED} readiness=${REQUIRE_XSS_BROWSER_READINESS})"
echo "[remote-verifier] Advisory budgets: failure<=${XSS_BROWSER_ADVISORY_MAX_FAILURE_RATE} unconfigured<=${XSS_BROWSER_ADVISORY_MAX_UNCONFIGURED_RATE}"
echo "[remote-verifier] Backend mode: ${VERIFIER_BACKEND}"
echo "[remote-verifier] Stability rounds: ${VERIFIER_STABILITY_ROUNDS}"

if [[ "${XSS_BROWSER_MODE}" != "off" && "${REQUIRE_XSS_BROWSER_READINESS}" == "1" ]]; then
  echo "[remote-verifier] Checking remote browser readiness"
  ssh_exec "${REMOTE_CMD}" <<'REMOTE'
set -euo pipefail

if [[ ! -d "${REMOTE_PROJECT_ROOT}" ]]; then
  echo "Remote project root does not exist: ${REMOTE_PROJECT_ROOT}" >&2
  exit 1
fi

cd "${REMOTE_PROJECT_ROOT}"
command -v node >/dev/null 2>&1
command -v npm >/dev/null 2>&1
echo "[remote-verifier] node=$(node --version)"
echo "[remote-verifier] npm=$(npm --version)"

node -e 'const v = require("playwright/package.json").version; console.log("[remote-verifier] playwright=" + v);'

driver_cmd_trimmed="$(printf '%s' "${XSS_BROWSER_DRIVER_CMD}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
if [[ -n "${driver_cmd_trimmed}" ]]; then
  driver_first="${driver_cmd_trimmed%% *}"
  if [[ "${driver_first}" == */* ]]; then
    if [[ ! -e "${driver_first}" ]]; then
      echo "Configured browser driver command first token path does not exist: ${driver_first}" >&2
      exit 1
    fi
  else
    if ! command -v "${driver_first}" >/dev/null 2>&1; then
      echo "Configured browser driver command executable not found: ${driver_first}" >&2
      exit 1
    fi
  fi
  echo "[remote-verifier] browser driver executable detected: ${driver_first}"
else
  echo "[remote-verifier] browser driver command is empty (advisory path only)." >&2
fi

if [[ "${XSS_BROWSER_MODE}" == "enforce" || "${VALIDATE_XSS_BROWSER_EXECUTION_CONFIRMED}" == "1" ]]; then
  node -e '
const { chromium } = require("playwright");
(async () => {
  const browser = await chromium.launch({ headless: true });
  console.log("[remote-verifier] chromium=" + browser.version());
  await browser.close();
})().catch((err) => {
  console.error("chromium readiness failed: " + (err && err.message ? err.message : String(err)));
  process.exit(1);
});
'
fi
REMOTE
fi

echo "[remote-verifier] Restarting lab with verifier enabled and resetting runtime state"
ssh_exec "${REMOTE_CMD}" <<'REMOTE'
set -euo pipefail

export PHP_TAINT_TRACE_ENABLE_VERIFIER=1
export PHP_TAINT_TRACE_VERIFIER_RUNTIME_DIR="${REMOTE_VERIFIER_DIR}"
export PHP_TAINT_TRACE_VERIFIER_REPLAY_TARGET=remote_lab
export PHP_TAINT_TRACE_VERIFIER_STABILITY_ROUNDS="${VERIFIER_STABILITY_ROUNDS}"
export PHP_TAINT_TRACE_ENABLE_OPCODE_HOOKS=1
export PHP_TAINT_TRACE_OPCODE_HOOK_PROFILE=safe
export PHP_TAINT_TRACE_LAB_EXTENSION_PROFILE="${EXTENSION_PROFILE}"
export PHP_TAINT_TRACE_LAB_ENABLE_XDEBUG=0

cd "${REMOTE_PROJECT_ROOT}"
bash scripts/remote_vuln_lab_manage.sh profile "${EXTENSION_PROFILE}"
bash scripts/remote_vuln_lab_manage.sh restart
bash scripts/remote_vuln_lab_manage.sh reset
rm -rf "${REMOTE_VERIFIER_DIR}"
mkdir -p "${REMOTE_VERIFIER_DIR}"
REMOTE

echo "[remote-verifier] Collecting remote capability snapshot"
CAPABILITIES_JSON="$(ssh_exec "${REMOTE_CMD}" <<'REMOTE'
set -euo pipefail

export PHP_TAINT_TRACE_LAB_EXTENSION_PROFILE="${EXTENSION_PROFILE}"
export PHP_TAINT_TRACE_ENABLE_OPCODE_HOOKS=1
export PHP_TAINT_TRACE_OPCODE_HOOK_PROFILE=safe
cd "${REMOTE_PROJECT_ROOT}"
bash scripts/remote_vuln_lab_manage.sh capabilities --json
REMOTE
)"

CAPABILITY_ASSERTIONS_JSON="$(python3 - "${CAPABILITIES_JSON}" <<'PY'
import json
import sys

payload = json.loads(sys.argv[1])
assertions = payload.get("assertions", {})
selected = {}
execution_modes = {}
for key in (
    "rce_exec",
    "rce_shell_exec",
    "rce_popen",
    "rce_passthru",
    "rce_proc_open",
    "rce_unserialize_template",
    "rce_include_or_eval",
    "rce_pcntl_exec",
    "rce_expect_popen",
    "rce_dl",
    "file_fopen",
    "file_readfile",
    "ssrf_curl_setopt",
    "ssrf_curl_setopt_array",
    "ssrf_curl_multi_setopt",
    "ssrf_curl_multi_setopt_array",
    "ssrf_fsockopen",
    "ssrf_get_headers",
    "ssrf_soapclient_construct",
    "ssrf_soapclient_location",
    "ssrf_soapclient_setlocation",
    "sqli_pg_prepare",
    "sqli_pg_execute",
    "sqli_pg_send_execute",
    "sqli_pdo_query",
    "sqli_pdo_exec",
    "sqli_sqlite3_querysingle",
    "sqli_sqlite3_query",
    "sqli_sqlite3_exec",
    "sqli_mysqli_execute_query",
    "sqli_sqlsrv_prepare",
    "sqli_sqlsrv_query",
    "sqli_oci_parse",
    "xxe_domdocument_load",
    "xxe_domdocument_loadxml",
    "xxe_xmlreader_open",
    "xxe_xmlreader_xml",
    "xxe_simplexml_load_string",
    "xxe_simplexml_load_file",
):
    row = assertions.get(key, {})
    selected[key] = bool(row.get("available", False))
    execution_modes[key] = str(row.get("execution_mode", ""))

out = {
    "extension_profile": payload.get("extension_profile", "base"),
    "assertions": selected,
    "assertion_execution_modes": execution_modes,
    "required_assertions_for_profile": payload.get("required_assertions_for_profile", []),
}
print(json.dumps(out, separators=(",", ":")))
PY
)"

REMOTE_VALIDATE_CMD="$(printf \
  "REMOTE_PROJECT_ROOT=%q REMOTE_VERIFIER_DIR=%q EXTENSION_PROFILE=%q CAPABILITY_ASSERTIONS_JSON=%q STRICT_EXTENSION_PROFILE=%q XSS_BROWSER_MODE=%q XSS_BROWSER_DRIVER_CMD=%q XSS_BROWSER_TIMEOUT_MS=%q VALIDATE_XSS_BROWSER_REASON=%q VALIDATE_XSS_BROWSER_EXECUTION_CONFIRMED=%q XSS_BROWSER_ADVISORY_MAX_FAILURE_RATE=%q XSS_BROWSER_ADVISORY_MAX_UNCONFIGURED_RATE=%q REQUIRE_XSS_BROWSER_READINESS=%q MAX_DEAD_LETTERS=%q VERIFIER_BACKEND=%q bash -s" \
  "${REMOTE_PROJECT_ROOT}" \
  "${REMOTE_VERIFIER_DIR}" \
  "${EXTENSION_PROFILE}" \
  "${CAPABILITY_ASSERTIONS_JSON}" \
  "${STRICT_EXTENSION_PROFILE}" \
  "${XSS_BROWSER_MODE}" \
  "${XSS_BROWSER_DRIVER_CMD}" \
  "${XSS_BROWSER_TIMEOUT_MS}" \
  "${VALIDATE_XSS_BROWSER_REASON}" \
  "${VALIDATE_XSS_BROWSER_EXECUTION_CONFIRMED}" \
  "${XSS_BROWSER_ADVISORY_MAX_FAILURE_RATE}" \
  "${XSS_BROWSER_ADVISORY_MAX_UNCONFIGURED_RATE}" \
  "${REQUIRE_XSS_BROWSER_READINESS}" \
  "${MAX_DEAD_LETTERS}" \
  "${VERIFIER_BACKEND}" \
)"

echo "[remote-verifier] Extension profile: ${EXTENSION_PROFILE} (strict=${STRICT_EXTENSION_PROFILE})"

echo "[remote-verifier] Triggering vulnerable requests across all categories"
ssh_exec "${REMOTE_CMD}" <<'REMOTE'
set -euo pipefail

http_get() {
  php -r '
$url = $argv[1];
$ctx = stream_context_create(array(
    "http" => array(
        "ignore_errors" => true,
        "timeout" => 4,
    ),
));
$body = @file_get_contents($url, false, $ctx);
if ($body === false) {
    fwrite(STDERR, "request failed: " . $url . PHP_EOL);
    exit(1);
}
' "$1"
}

http_get 'http://127.0.0.1:19081/?name=%3Cscript%3Ephase-d-xss%3C%2Fscript%3E'
http_get 'http://127.0.0.1:19082/?cmd=echo%20xtanzi'
http_get 'http://127.0.0.1:19083/?path=%2Fetc%2Fhostname'
http_get 'http://127.0.0.1:19083/?sink=fopen&path=%2Fetc%2Fhostname'
http_get 'http://127.0.0.1:19083/?sink=readfile&path=%2Fetc%2Fhostname'
http_get 'http://127.0.0.1:19084/?url=http%3A%2F%2F127.0.0.1%3A19081%2F%3Fname%3Dxtanzi'
http_get 'http://127.0.0.1:19085/?q=SELECT%20username%20FROM%20users%20WHERE%20id%20%3D%201'
http_get 'http://127.0.0.1:19086/?resource_id=42&actor_id=1043&mode=vuln'
http_get 'http://127.0.0.1:19087/?xml=%3C!DOCTYPE%20root%20%5B%3C!ENTITY%20xxe%20SYSTEM%20%22http%3A%2F%2F127.0.0.1%3A19081%2F%3Fname%3Dphase-d-xxe%22%3E%5D%3E%3Croot%3E%26xxe%3B%3C%2Froot%3E'
http_get 'http://127.0.0.1:19084/?sink=curl_setopt&url=http%3A%2F%2F127.0.0.1%3A19081%2F%3Fname%3Dxtanzi'
http_get 'http://127.0.0.1:19084/?sink=curl_setopt_array&url=http%3A%2F%2F127.0.0.1%3A19081%2F%3Fname%3Dxtanzi'
http_get 'http://127.0.0.1:19084/?sink=curl_multi_setopt&url=http%3A%2F%2F127.0.0.1%3A19081%2F%3Fname%3Dxtanzi'
http_get 'http://127.0.0.1:19084/?sink=curl_multi_setopt_array&url=http%3A%2F%2F127.0.0.1%3A19081%2F%3Fname%3Dxtanzi'
http_get 'http://127.0.0.1:19084/?sink=fsockopen&url=http%3A%2F%2F127.0.0.1%3A19081%2F%3Fname%3Dxtanzi'
http_get 'http://127.0.0.1:19084/?sink=get_headers&url=http%3A%2F%2F127.0.0.1%3A19081%2F%3Fname%3Dxtanzi'
http_get 'http://127.0.0.1:19084/?sink=soapclient_construct&url=http%3A%2F%2F127.0.0.1%3A19081%2F%3Fname%3Dxtanzi'
http_get 'http://127.0.0.1:19084/?sink=soapclient_location&url=http%3A%2F%2F127.0.0.1%3A19081%2F%3Fname%3Dxtanzi'
http_get 'http://127.0.0.1:19084/?sink=soapclient_setlocation&url=http%3A%2F%2F127.0.0.1%3A19081%2F%3Fname%3Dxtanzi'
http_get 'http://127.0.0.1:19087/?sink=dom_load&xml=%3C!DOCTYPE%20root%20%5B%3C!ENTITY%20xxe%20SYSTEM%20%22http%3A%2F%2F127.0.0.1%3A19081%2F%3Fname%3Dphase-d-xxe-dom%22%3E%5D%3E%3Croot%3E%26xxe%3B%3C%2Froot%3E'
http_get 'http://127.0.0.1:19087/?sink=dom_loadxml&xml=%3C!DOCTYPE%20root%20%5B%3C!ENTITY%20xxe%20SYSTEM%20%22http%3A%2F%2F127.0.0.1%3A19081%2F%3Fname%3Dphase-d-xxe-domxml%22%3E%5D%3E%3Croot%3E%26xxe%3B%3C%2Froot%3E'
http_get 'http://127.0.0.1:19087/?sink=xmlreader_open&xml=%3C!DOCTYPE%20root%20%5B%3C!ENTITY%20xxe%20SYSTEM%20%22http%3A%2F%2F127.0.0.1%3A19081%2F%3Fname%3Dphase-d-xxe-reader%22%3E%5D%3E%3Croot%3E%26xxe%3B%3C%2Froot%3E'
http_get 'http://127.0.0.1:19087/?sink=xmlreader_xml&xml=%3C!DOCTYPE%20root%20%5B%3C!ENTITY%20xxe%20SYSTEM%20%22http%3A%2F%2F127.0.0.1%3A19081%2F%3Fname%3Dphase-d-xxe-readerxml%22%3E%5D%3E%3Croot%3E%26xxe%3B%3C%2Froot%3E'
http_get 'http://127.0.0.1:19087/?sink=simplexml&xml=%3C!DOCTYPE%20root%20%5B%3C!ENTITY%20xxe%20SYSTEM%20%22http%3A%2F%2F127.0.0.1%3A19081%2F%3Fname%3Dphase-d-xxe-simplexml%22%3E%5D%3E%3Croot%3E%26xxe%3B%3C%2Froot%3E'
http_get 'http://127.0.0.1:19087/?sink=simplexml_file&xml=%3C!DOCTYPE%20root%20%5B%3C!ENTITY%20xxe%20SYSTEM%20%22http%3A%2F%2F127.0.0.1%3A19081%2F%3Fname%3Dphase-d-xxe-simplexmlfile%22%3E%5D%3E%3Croot%3E%26xxe%3B%3C%2Froot%3E'
http_get 'http://127.0.0.1:19082/?sink=pcntl_exec&cmd=%2Fdefinitely%2Fnot%2Ffound_xtanzi'
http_get 'http://127.0.0.1:19082/?sink=expect_popen&cmd=echo%20xtanzi'
http_get 'http://127.0.0.1:19082/?sink=dl&cmd=nonexistent_xtanzi_extension'
http_get 'http://127.0.0.1:19082/?sink=exec&cmd=echo%20xtanzi'
http_get 'http://127.0.0.1:19082/?sink=shell_exec&cmd=echo%20xtanzi'
http_get 'http://127.0.0.1:19082/?sink=popen&cmd=echo%20xtanzi'
http_get 'http://127.0.0.1:19082/?sink=passthru&cmd=echo%20xtanzi'
http_get 'http://127.0.0.1:19082/?sink=proc_open&cmd=echo%20xtanzi'
http_get 'http://127.0.0.1:19082/?sink=unserialize_template&cmd=echo%20xtanzi'
http_get 'http://127.0.0.1:19082/?sink=eval&cmd=echo%20%22xtanzi%22%3B'
http_get 'http://127.0.0.1:19085/?sink=pg_prepare&q=xtanzi'
http_get 'http://127.0.0.1:19085/?sink=pg_execute&q=xtanzi'
http_get 'http://127.0.0.1:19085/?sink=pg_send_execute&q=xtanzi'
http_get 'http://127.0.0.1:19085/?sink=pdo_query&q=SELECT%20%27xtanzi%27%20AS%20username'
http_get 'http://127.0.0.1:19085/?sink=pdo_exec&q=SELECT%20%27xtanzi%27%20AS%20username'
http_get 'http://127.0.0.1:19085/?sink=sqlite3_querysingle&q=SELECT%20%27xtanzi%27'
http_get 'http://127.0.0.1:19085/?sink=sqlite3_query&q=SELECT%20%27xtanzi%27'
http_get 'http://127.0.0.1:19085/?sink=sqlite3_exec&q=SELECT%20%27xtanzi%27'
http_get 'http://127.0.0.1:19085/?sink=mysqli_execute_query&q=SELECT%20xtanzi'
http_get 'http://127.0.0.1:19085/?sink=sqlsrv_prepare&q=SELECT%20xtanzi'
http_get 'http://127.0.0.1:19085/?sink=sqlsrv_query&q=SELECT%20xtanzi'
http_get 'http://127.0.0.1:19085/?sink=oci_parse&q=SELECT%20xtanzi%20FROM%20dual'
REMOTE

echo "[remote-verifier] Running verifier backend (${VERIFIER_BACKEND})"
ssh_exec "${REMOTE_CMD}" <<'REMOTE'
set -euo pipefail

cd "${REMOTE_PROJECT_ROOT}"
export PHP_TAINT_TRACE_VERIFIER_RUNTIME_DIR="${REMOTE_VERIFIER_DIR}"
export PHP_TAINT_TRACE_VERIFIER_REPLAY_TARGET=remote_lab
export PHP_TAINT_TRACE_VERIFIER_REMOTE_HOST=127.0.0.1
export PHP_TAINT_TRACE_VERIFIER_BATCH_SIZE=200
export PHP_TAINT_TRACE_VERIFIER_STABILITY_ROUNDS="${VERIFIER_STABILITY_ROUNDS}"
export PHP_TAINT_TRACE_VERIFIER_XSS_BROWSER_TIMEOUT_MS="${XSS_BROWSER_TIMEOUT_MS}"
export PHP_TAINT_TRACE_VERIFIER_XSS_BROWSER_DRIVER_CMD="${XSS_BROWSER_DRIVER_CMD}"

case "${XSS_BROWSER_MODE}" in
  off)
    export PHP_TAINT_TRACE_VERIFIER_XSS_BROWSER_ENABLED=0
    export PHP_TAINT_TRACE_VERIFIER_XSS_BROWSER_ENFORCE=0
    ;;
  advisory)
    export PHP_TAINT_TRACE_VERIFIER_XSS_BROWSER_ENABLED=1
    export PHP_TAINT_TRACE_VERIFIER_XSS_BROWSER_ENFORCE=0
    ;;
  enforce)
    export PHP_TAINT_TRACE_VERIFIER_XSS_BROWSER_ENABLED=1
    export PHP_TAINT_TRACE_VERIFIER_XSS_BROWSER_ENFORCE=1
    ;;
esac

run_php_worker_drain() {
  local output=""
  output="$(php scripts/run_verifier_worker.php --drain --max-cycles=20)"
  echo "${output}"

  local pending=""
  pending="$(printf '%s\n' "${output}" | sed -n 's/.*pending=\([0-9][0-9]*\).*/\1/p' | tail -n 1)"
  if [[ -n "${pending}" ]] && [[ "${pending}" -ne 0 ]]; then
    echo "[remote-verifier] worker drain did not converge to pending=0 (last_pending=${pending})" >&2
    exit 1
  fi
}

run_php_worker_drain
REMOTE

echo "[remote-verifier] Validating verifier results"
if ! ssh_exec "${REMOTE_VALIDATE_CMD}" <<'REMOTE'
set -euo pipefail

php -r '
$jobsPath = $argv[1] . "/jobs.jsonl";
$resultsPath = $argv[1] . "/results.jsonl";
$decisionsPath = $argv[1] . "/decisions.jsonl";
$dbgpDecisionsPath = $argv[1] . "/decisions_dbgp.jsonl";
$browserMode = strtolower((string) ($argv[2] ?? "off"));
$validateBrowserReason = filter_var($argv[3] ?? "0", FILTER_VALIDATE_BOOL);
$validateBrowserExecutionConfirmed = filter_var($argv[4] ?? "0", FILTER_VALIDATE_BOOL);
$advisoryMaxFailureRate = max(0.0, min(1.0, (float) ($argv[5] ?? "0.25")));
$advisoryMaxUnconfiguredRate = max(0.0, min(1.0, (float) ($argv[6] ?? "0.10")));
$maxDeadLetters = max(0, (int) ($argv[7] ?? "0"));
$capabilityPayload = json_decode((string) ($argv[8] ?? "{}"), true);
$strictExtensionProfile = filter_var((string) ($argv[9] ?? "0"), FILTER_VALIDATE_BOOL);
$requestedProfile = strtolower(trim((string) ($argv[10] ?? "base")));
$summaryPath = (string) ($argv[11] ?? "");
$verifierBackend = strtolower(trim((string) ($argv[12] ?? "php_worker")));
$workerEnabled = ($verifierBackend === "php_worker" || $verifierBackend === "both");
$dbgpEnabled = ($verifierBackend === "dbgp_batch" || $verifierBackend === "both");

$jobLines = @file($jobsPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
if (!is_array($jobLines)) {
    fwrite(STDERR, "missing verifier jobs at " . $jobsPath . PHP_EOL);
    exit(1);
}

$lines = array();
if ($workerEnabled) {
    $lines = @file($resultsPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (!is_array($lines)) {
        fwrite(STDERR, "missing verifier results at " . $resultsPath . PHP_EOL);
        exit(1);
    }
}

$decisionLines = array();
if ($workerEnabled) {
    $decisionLines = @file($decisionsPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (!is_array($decisionLines)) {
        fwrite(STDERR, "missing verifier decisions at " . $decisionsPath . PHP_EOL);
        exit(1);
    }
}

$dbgpDecisionLines = array();
if ($dbgpEnabled) {
    $dbgpDecisionLines = @file($dbgpDecisionsPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (!is_array($dbgpDecisionLines)) {
        fwrite(STDERR, "missing dbgp verifier decisions at " . $dbgpDecisionsPath . PHP_EOL);
        exit(1);
    }
}

$capabilityAssertions = array();
if (is_array($capabilityPayload["assertions"] ?? null)) {
    foreach ($capabilityPayload["assertions"] as $assertion => $value) {
        $capabilityAssertions[(string) $assertion] = (bool) $value;
    }
}
$assertionExecutionModes = array();
if (is_array($capabilityPayload["assertion_execution_modes"] ?? null)) {
    foreach ($capabilityPayload["assertion_execution_modes"] as $assertion => $value) {
        $assertionExecutionModes[(string) $assertion] = is_scalar($value) ? (string) $value : "";
    }
}

$requiredByProfile = array();
if (is_array($capabilityPayload["required_assertions_for_profile"] ?? null)) {
    foreach ($capabilityPayload["required_assertions_for_profile"] as $assertionNameRaw) {
        $assertionName = is_scalar($assertionNameRaw) ? trim((string) $assertionNameRaw) : "";
        if ($assertionName !== "") {
            $requiredByProfile[$assertionName] = true;
        }
    }
    $requiredByProfile = array_keys($requiredByProfile);
} else {
    if ($requestedProfile === "extended_sql" || $requestedProfile === "extended_all") {
        $requiredByProfile = array_merge($requiredByProfile, array(
            "sqli_pg_prepare",
            "sqli_pg_execute",
            "sqli_pg_send_execute",
            "sqli_pdo_query",
            "sqli_pdo_exec",
            "sqli_sqlite3_querysingle",
            "sqli_sqlite3_query",
            "sqli_sqlite3_exec",
            "sqli_mysqli_execute_query",
            "sqli_sqlsrv_prepare",
            "sqli_sqlsrv_query",
            "sqli_oci_parse",
        ));
    }
    if ($requestedProfile === "extended_rce" || $requestedProfile === "extended_all") {
        $requiredByProfile = array_merge($requiredByProfile, array(
            "rce_exec",
            "rce_shell_exec",
            "rce_popen",
            "rce_passthru",
            "rce_proc_open",
            "rce_unserialize_template",
            "rce_include_or_eval",
            "rce_pcntl_exec",
            "rce_expect_popen",
            "rce_dl",
        ));
    }
    $requiredByProfile = array_values(array_unique($requiredByProfile));
}

$deadLettersPath = $argv[1] . "/dead_letters.jsonl";
$deadLetterLines = @file($deadLettersPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
if (!is_array($deadLetterLines)) {
    $deadLetterLines = array();
}

$required = array("rce", "ssrf", "sqli", "file", "xss", "idor", "xxe");
$workerConfirmedResultCategories = array();
$workerConfirmedDecisionCategories = array();
$dbgpConfirmedDecisionCategories = array();
$xssDecisionHadBrowserReason = false;
$xssDecisionConfirmedSeen = false;
$xssBrowserExecutionConfirmedCount = 0;
$xssBrowserFailureCount = 0;
$xssBrowserUnconfiguredCount = 0;
$xssBrowserConfirmedDecisionCount = 0;

if ($workerEnabled) {
    foreach ($lines as $line) {
        $row = json_decode($line, true);
        if (!is_array($row)) {
            continue;
        }

        if (($row["outcome"] ?? null) !== "confirmed") {
            continue;
        }

        $category = $row["metadata"]["sink_category"] ?? null;
        if (!is_string($category)) {
            continue;
        }

        $workerConfirmedResultCategories[$category] = true;
    }

    $missingWorkerResultCategories = array();
    foreach ($required as $category) {
        if (!isset($workerConfirmedResultCategories[$category])) {
            $missingWorkerResultCategories[] = $category;
        }
    }
    if ($missingWorkerResultCategories !== array()) {
        fwrite(STDERR, "missing confirmed verifier categories: " . implode(", ", $missingWorkerResultCategories) . PHP_EOL);
        exit(1);
    }

    foreach ($decisionLines as $line) {
        $row = json_decode($line, true);
        if (!is_array($row)) {
            continue;
        }

        if (($row["decision_tier"] ?? null) !== "confirmed") {
            continue;
        }

        $metadata = $row["metadata"] ?? null;
        if (!is_array($metadata)) {
            continue;
        }

        $scoreBreakdown = $row["score_breakdown"] ?? null;
        if (!is_array($scoreBreakdown)) {
            fwrite(STDERR, "decision row missing score_breakdown" . PHP_EOL);
            exit(1);
        }

        if (($scoreBreakdown["formula_version"] ?? null) !== "phase_c_v1_step27") {
            fwrite(STDERR, "decision row missing phase_c_v1_step27 formula_version" . PHP_EOL);
            exit(1);
        }

        if (!is_array($row["reason_codes"] ?? null)) {
            fwrite(STDERR, "decision row missing reason_codes array" . PHP_EOL);
            exit(1);
        }

        $category = $metadata["sink_category"] ?? null;
        if (is_string($category) && $category !== "") {
            $workerConfirmedDecisionCategories[$category] = true;
            if ($category === "xss") {
                $xssDecisionConfirmedSeen = true;
                $xssBrowserConfirmedDecisionCount++;
                $hasBrowserReason = false;
                $hasExecutionConfirmed = false;
                $hasUnconfigured = false;
                $hasBrowserFailure = false;
                foreach ($row["reason_codes"] as $reasonCodeRaw) {
                    $reasonCode = is_scalar($reasonCodeRaw) ? (string) $reasonCodeRaw : "";
                    if ($reasonCode !== "" && str_starts_with($reasonCode, "VERIFIER_XSS_BROWSER_")) {
                        $xssDecisionHadBrowserReason = true;
                        $hasBrowserReason = true;
                    }
                    if ($reasonCode === "VERIFIER_XSS_BROWSER_EXECUTION_CONFIRMED") {
                        $hasExecutionConfirmed = true;
                    }
                    if ($reasonCode === "VERIFIER_XSS_BROWSER_PROBE_UNCONFIGURED") {
                        $hasUnconfigured = true;
                    }
                    if (in_array($reasonCode, array(
                        "VERIFIER_XSS_BROWSER_PROBE_FAILED",
                        "VERIFIER_XSS_BROWSER_EXECUTION_NOT_OBSERVED",
                        "VERIFIER_XSS_BROWSER_REQUEST_PARSE_FAILED",
                        "VERIFIER_XSS_BROWSER_METHOD_BLOCKED",
                        "VERIFIER_XSS_BROWSER_TARGET_PARAM_MISSING",
                    ), true)) {
                        $hasBrowserFailure = true;
                    }
                }
                if ($hasExecutionConfirmed) {
                    $xssBrowserExecutionConfirmedCount++;
                }
                if ($hasUnconfigured) {
                    $xssBrowserUnconfiguredCount++;
                }
                if ($hasBrowserFailure) {
                    $xssBrowserFailureCount++;
                }
                if ($validateBrowserReason && !$hasBrowserReason) {
                    fwrite(STDERR, "browser mode enabled but confirmed xss decision had no VERIFIER_XSS_BROWSER_* reason code." . PHP_EOL);
                    exit(1);
                }
            }
        }
    }

    $missingWorkerDecisionCategories = array();
    foreach ($required as $category) {
        if (!isset($workerConfirmedDecisionCategories[$category])) {
            $missingWorkerDecisionCategories[] = $category;
        }
    }
    if ($missingWorkerDecisionCategories !== array()) {
        fwrite(STDERR, "missing confirmed decision tiers for categories: " . implode(", ", $missingWorkerDecisionCategories) . PHP_EOL);
        exit(1);
    }
}

if ($dbgpEnabled) {
    foreach ($dbgpDecisionLines as $line) {
        $row = json_decode($line, true);
        if (!is_array($row)) {
            continue;
        }
        if (($row["outcome"] ?? null) !== "confirmed") {
            continue;
        }

        $metadata = is_array($row["metadata"] ?? null) ? $row["metadata"] : array();
        $trigger = is_array($metadata["trigger"] ?? null) ? $metadata["trigger"] : array();
        $category = "";
        if (is_scalar($trigger["sinkCategory"] ?? null)) {
            $category = trim((string) $trigger["sinkCategory"]);
        }
        if ($category === "" && is_scalar($trigger["sink_category"] ?? null)) {
            $category = trim((string) $trigger["sink_category"]);
        }
        if ($category === "" && is_scalar($metadata["sink_category"] ?? null)) {
            $category = trim((string) $metadata["sink_category"]);
        }
        if ($category === "") {
            continue;
        }

        $dbgpConfirmedDecisionCategories[$category] = true;
    }

    $missingDbgpDecisionCategories = array();
    foreach ($required as $category) {
        if (!isset($dbgpConfirmedDecisionCategories[$category])) {
            $missingDbgpDecisionCategories[] = $category;
        }
    }
    if ($missingDbgpDecisionCategories !== array()) {
        fwrite(STDERR, "missing confirmed dbgp decisions for categories: " . implode(", ", $missingDbgpDecisionCategories) . PHP_EOL);
        exit(1);
    }
}

if ($workerEnabled && $dbgpEnabled) {
    $workerMissingInDbgp = array();
    $dbgpMissingInWorker = array();
    foreach ($required as $category) {
        if (isset($workerConfirmedDecisionCategories[$category]) && !isset($dbgpConfirmedDecisionCategories[$category])) {
            $workerMissingInDbgp[] = $category;
        }
        if (isset($dbgpConfirmedDecisionCategories[$category]) && !isset($workerConfirmedDecisionCategories[$category])) {
            $dbgpMissingInWorker[] = $category;
        }
    }
    if ($workerMissingInDbgp !== array() || $dbgpMissingInWorker !== array()) {
        fwrite(STDERR, "backend parity mismatch detected." . PHP_EOL);
        if ($workerMissingInDbgp !== array()) {
            fwrite(STDERR, "  worker-only categories: " . implode(", ", $workerMissingInDbgp) . PHP_EOL);
        }
        if ($dbgpMissingInWorker !== array()) {
            fwrite(STDERR, "  dbgp-only categories: " . implode(", ", $dbgpMissingInWorker) . PHP_EOL);
        }
        exit(1);
    }
    echo "[ok] backend parity: worker and dbgp confirmed the same required category set." . PHP_EOL;
}

$jobsById = array();
foreach ($jobLines as $line) {
    $row = json_decode($line, true);
    if (!is_array($row)) {
        continue;
    }
    $jobId = (string) ($row["job_id"] ?? "");
    if ($jobId === "") {
        continue;
    }
    $jobsById[$jobId] = $row;
}

$resultsByJobId = array();
foreach ($lines as $line) {
    $row = json_decode($line, true);
    if (!is_array($row)) {
        continue;
    }
    $jobId = (string) ($row["job_id"] ?? "");
    if ($jobId === "") {
        continue;
    }
    $resultsByJobId[$jobId] = $row;
}

$optionalVerifierAssertions = array(
    "rce_exec" => array("sink_name" => "exec", "sink_category" => "rce", "request_uri_contains" => "sink=exec"),
    "rce_shell_exec" => array("sink_name" => "shell_exec", "sink_category" => "rce", "request_uri_contains" => "sink=shell_exec"),
    "rce_popen" => array("sink_name" => "popen", "sink_category" => "rce", "request_uri_contains" => "sink=popen"),
    "rce_passthru" => array("sink_name" => "passthru", "sink_category" => "rce", "request_uri_contains" => "sink=passthru"),
    "rce_proc_open" => array("sink_name" => "proc_open", "sink_category" => "rce", "request_uri_contains" => "sink=proc_open"),
    "rce_unserialize_template" => array("sink_name" => "unserialize", "sink_category" => "rce", "request_uri_contains" => "sink=unserialize_template"),
    "rce_include_or_eval" => array("sink_name" => "include_or_eval", "sink_category" => "rce", "request_uri_contains" => "sink=eval"),
    "rce_pcntl_exec" => array("sink_name" => "pcntl_exec", "sink_category" => "rce", "request_uri_contains" => "sink=pcntl_exec"),
    "rce_expect_popen" => array("sink_name" => "expect_popen", "sink_category" => "rce", "request_uri_contains" => "sink=expect_popen"),
    "rce_dl" => array("sink_name" => "dl", "sink_category" => "rce", "request_uri_contains" => "sink=dl"),
    "file_fopen" => array("sink_name" => "fopen", "sink_category" => "file", "request_uri_contains" => "sink=fopen"),
    "file_readfile" => array("sink_name" => "readfile", "sink_category" => "file", "request_uri_contains" => "sink=readfile"),
    "ssrf_curl_setopt" => array("sink_name" => "curl_exec", "sink_category" => "ssrf", "request_uri_contains" => "sink=curl_setopt"),
    "ssrf_curl_setopt_array" => array("sink_name" => "curl_exec", "sink_category" => "ssrf", "request_uri_contains" => "sink=curl_setopt_array"),
    "ssrf_curl_multi_setopt" => array("sink_name" => "curl_multi_exec", "sink_category" => "ssrf", "request_uri_contains" => "sink=curl_multi_setopt"),
    "ssrf_curl_multi_setopt_array" => array("sink_name" => "curl_multi_exec", "sink_category" => "ssrf", "request_uri_contains" => "sink=curl_multi_setopt_array"),
    "ssrf_fsockopen" => array("sink_name" => "fsockopen", "sink_category" => "ssrf", "request_uri_contains" => "sink=fsockopen"),
    "ssrf_get_headers" => array("sink_name" => "get_headers", "sink_category" => "ssrf", "request_uri_contains" => "sink=get_headers"),
    "ssrf_soapclient_construct" => array("sink_name" => "SoapClient::__construct", "sink_category" => "ssrf", "request_uri_contains" => "sink=soapclient_construct"),
    "ssrf_soapclient_location" => array("sink_name" => "SoapClient::__construct", "sink_category" => "ssrf", "request_uri_contains" => "sink=soapclient_location"),
    "ssrf_soapclient_setlocation" => array("sink_name" => "SoapClient::__setLocation", "sink_category" => "ssrf", "request_uri_contains" => "sink=soapclient_setlocation"),
    "sqli_pg_prepare" => array("sink_name" => "pg_prepare", "sink_category" => "sqli", "request_uri_contains" => "sink=pg_prepare"),
    "sqli_pg_execute" => array("sink_name" => "pg_execute", "sink_category" => "sqli", "request_uri_contains" => "sink=pg_execute"),
    "sqli_pg_send_execute" => array("sink_name" => "pg_send_execute", "sink_category" => "sqli", "request_uri_contains" => "sink=pg_send_execute"),
    "sqli_pdo_query" => array("sink_name" => "PDO::query", "sink_category" => "sqli", "request_uri_contains" => "sink=pdo_query"),
    "sqli_pdo_exec" => array("sink_name" => "PDO::exec", "sink_category" => "sqli", "request_uri_contains" => "sink=pdo_exec"),
    "sqli_sqlite3_querysingle" => array("sink_name" => "SQLite3::querySingle", "sink_category" => "sqli", "request_uri_contains" => "sink=sqlite3_querysingle"),
    "sqli_sqlite3_query" => array("sink_name" => "SQLite3::query", "sink_category" => "sqli", "request_uri_contains" => "sink=sqlite3_query"),
    "sqli_sqlite3_exec" => array("sink_name" => "SQLite3::exec", "sink_category" => "sqli", "request_uri_contains" => "sink=sqlite3_exec"),
    "sqli_mysqli_execute_query" => array("sink_name" => "mysqli_execute_query", "sink_category" => "sqli", "request_uri_contains" => "sink=mysqli_execute_query"),
    "sqli_sqlsrv_prepare" => array("sink_name" => "sqlsrv_prepare", "sink_category" => "sqli", "request_uri_contains" => "sink=sqlsrv_prepare"),
    "sqli_sqlsrv_query" => array("sink_name" => "sqlsrv_query", "sink_category" => "sqli", "request_uri_contains" => "sink=sqlsrv_query"),
    "sqli_oci_parse" => array("sink_name" => "oci_parse", "sink_category" => "sqli", "request_uri_contains" => "sink=oci_parse"),
    "xxe_domdocument_load" => array("sink_name" => "DOMDocument::load", "sink_category" => "xxe", "request_uri_contains" => "sink=dom_load"),
    "xxe_domdocument_loadxml" => array("sink_name" => "DOMDocument::loadXML", "sink_category" => "xxe", "request_uri_contains" => "sink=dom_loadxml"),
    "xxe_xmlreader_open" => array("sink_name" => "XMLReader::open", "sink_category" => "xxe", "request_uri_contains" => "sink=xmlreader_open"),
    "xxe_xmlreader_xml" => array("sink_name" => "XMLReader::XML", "sink_category" => "xxe", "request_uri_contains" => "sink=xmlreader_xml"),
    "xxe_simplexml_load_string" => array("sink_name" => "simplexml_load_string", "sink_category" => "xxe", "request_uri_contains" => "sink=simplexml"),
    "xxe_simplexml_load_file" => array("sink_name" => "simplexml_load_file", "sink_category" => "xxe", "request_uri_contains" => "sink=simplexml_file"),
);

$optionalExecuted = 0;
$optionalSkipped = 0;
$optionalFailures = array();
if ($workerEnabled) {
    foreach ($optionalVerifierAssertions as $assertion => $target) {
        $available = (bool) ($capabilityAssertions[$assertion] ?? false);
        if (!$available) {
            $optionalSkipped++;
            echo "[skip] " . $assertion . " => capability unavailable" . PHP_EOL;
            if ($strictExtensionProfile && in_array($assertion, $requiredByProfile, true)) {
                $optionalFailures[] = $assertion . ": strict extension profile requires capability but it is unavailable";
            }
            continue;
        }

        $optionalExecuted++;
        $expectedSinkName = (string) $target["sink_name"];
        $requestUriContains = isset($target["request_uri_contains"]) && is_scalar($target["request_uri_contains"])
            ? (string) $target["request_uri_contains"]
            : "";
        if ($assertion === "rce_dl" && (string) ($assertionExecutionModes[$assertion] ?? "") === "cli_sidecar") {
            $expectedSinkName = "proc_open";
        }
        $matchingJobId = null;
        foreach ($jobsById as $jobId => $jobRow) {
            $candidate = $jobRow["candidate_snapshot"] ?? null;
            if (!is_array($candidate)) {
                continue;
            }
            $sinkName = (string) ($candidate["sink_name"] ?? "");
            $sinkCategory = (string) ($candidate["sink_category"] ?? "");
            if ($requestUriContains !== "") {
                $requestEvidence = is_array($candidate["request_evidence"] ?? null) ? $candidate["request_evidence"] : array();
                $requestUri = is_scalar($requestEvidence["request_uri"] ?? null) ? (string) $requestEvidence["request_uri"] : "";
                if (!str_contains($requestUri, $requestUriContains)) {
                    continue;
                }
            }
            if ($sinkName === $expectedSinkName && $sinkCategory === (string) $target["sink_category"]) {
                $matchingJobId = $jobId;
                break;
            }
        }

        if (!is_string($matchingJobId)) {
            $optionalFailures[] = $assertion . ": expected verifier job for sink "
                . $expectedSinkName . "/" . $target["sink_category"] . " not found";
            continue;
        }

        $resultRow = $resultsByJobId[$matchingJobId] ?? null;
        if (!is_array($resultRow)) {
            $optionalFailures[] = $assertion . ": verifier job " . $matchingJobId . " has no result row";
            continue;
        }

        $outcome = (string) ($resultRow["outcome"] ?? "");
        if ($outcome === "") {
            $optionalFailures[] = $assertion . ": verifier job " . $matchingJobId . " has empty outcome";
            continue;
        }

        echo "[ok] " . $assertion . " => job/result observed (sink=" . $expectedSinkName . ", outcome=" . $outcome . ")" . PHP_EOL;
    }

    if ($optionalFailures !== array()) {
        fwrite(STDERR, "extension verifier assertion failures:" . PHP_EOL);
        foreach ($optionalFailures as $line) {
            fwrite(STDERR, "  - " . $line . PHP_EOL);
        }
        exit(1);
    }

    echo sprintf(
        "[ok] extension verifier assertions summary: executed=%d skipped=%d strict=%s profile=%s",
        $optionalExecuted,
        $optionalSkipped,
        $strictExtensionProfile ? "true" : "false",
        $requestedProfile
    ) . PHP_EOL;
} else {
    $optionalSkipped = count($optionalVerifierAssertions);
    echo "[skip] extension verifier assertion checks require php_worker backend; skipped for dbgp_batch-only mode." . PHP_EOL;
}

if ($summaryPath !== "") {
    $summaryDir = dirname($summaryPath);
    if (!is_dir($summaryDir)) {
        @mkdir($summaryDir, 0775, true);
    }
    $total = $optionalExecuted + $optionalSkipped;
    $payload = array(
        "generated_at" => gmdate("c"),
        "script" => "run_remote_verifier_tests.sh",
        "verifier_backend" => $verifierBackend,
        "profile" => $requestedProfile,
        "strict" => (bool) $strictExtensionProfile,
        "optional_assertions_total" => $total,
        "optional_assertions_executed" => $optionalExecuted,
        "optional_assertions_skipped" => $optionalSkipped,
        "skip_rate" => $total > 0 ? round((float) $optionalSkipped / (float) $total, 6) : 0.0,
        "worker_confirmed_result_categories" => array_keys($workerConfirmedResultCategories),
        "worker_confirmed_decision_categories" => array_keys($workerConfirmedDecisionCategories),
        "dbgp_confirmed_decision_categories" => array_keys($dbgpConfirmedDecisionCategories),
        "capability_assertions" => $capabilityAssertions,
        "assertion_execution_modes" => $assertionExecutionModes,
        "required_assertions_for_profile" => $requiredByProfile,
    );
    $encoded = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    if (is_string($encoded)) {
        @file_put_contents($summaryPath, $encoded . PHP_EOL);
    }
}

if ($workerEnabled) {
    if ($browserMode !== "off" && $validateBrowserReason) {
        if (!$xssDecisionConfirmedSeen) {
            fwrite(STDERR, "browser mode enabled but no confirmed xss decision was present for browser reason validation." . PHP_EOL);
            exit(1);
        }
    }

    if ($browserMode !== "off" && $validateBrowserExecutionConfirmed) {
        if ($xssBrowserExecutionConfirmedCount < 1) {
            fwrite(STDERR, "browser execution-confirmed validation enabled but no confirmed xss decision contained VERIFIER_XSS_BROWSER_EXECUTION_CONFIRMED." . PHP_EOL);
            exit(1);
        }
    }

    if ($browserMode === "advisory" && $xssBrowserConfirmedDecisionCount > 0) {
        $failureRate = $xssBrowserFailureCount / $xssBrowserConfirmedDecisionCount;
        $unconfiguredRate = $xssBrowserUnconfiguredCount / $xssBrowserConfirmedDecisionCount;
        if ($failureRate > $advisoryMaxFailureRate) {
            fwrite(STDERR, sprintf(
                "xss browser advisory failure budget exceeded: failure_rate=%.4f threshold=%.4f%s",
                $failureRate,
                $advisoryMaxFailureRate,
                PHP_EOL
            ));
            exit(1);
        }
        if ($unconfiguredRate > $advisoryMaxUnconfiguredRate) {
            fwrite(STDERR, sprintf(
                "xss browser advisory unconfigured budget exceeded: unconfigured_rate=%.4f threshold=%.4f%s",
                $unconfiguredRate,
                $advisoryMaxUnconfiguredRate,
                PHP_EOL
            ));
            exit(1);
        }
        echo sprintf(
            "[ok] xss browser advisory budgets: execution_confirmed=%d/%d failure_rate=%.4f unconfigured_rate=%.4f",
            $xssBrowserExecutionConfirmedCount,
            $xssBrowserConfirmedDecisionCount,
            $failureRate,
            $unconfiguredRate
        ) . PHP_EOL;
    }
} elseif ($browserMode !== "off") {
    echo "[skip] xss browser reason-budget checks require php_worker decision tiers; skipped for dbgp_batch-only mode." . PHP_EOL;
}

$deadLetterCount = 0;
foreach ($deadLetterLines as $line) {
    $row = json_decode($line, true);
    if (!is_array($row)) {
        continue;
    }
    $deadLetterCount++;
}
if ($deadLetterCount > $maxDeadLetters) {
    fwrite(STDERR, sprintf(
        "dead letter budget exceeded: dead_letters=%d max_dead_letters=%d%s",
        $deadLetterCount,
        $maxDeadLetters,
        PHP_EOL
    ));
    exit(1);
}
echo sprintf("[ok] dead letters: %d/%d", $deadLetterCount, $maxDeadLetters) . PHP_EOL;

if ($workerEnabled) {
    echo "[ok] confirmed worker result categories: " . implode(", ", $required) . PHP_EOL;
    echo "[ok] confirmed worker decision tiers: " . implode(", ", $required) . PHP_EOL;
}
if ($dbgpEnabled) {
    echo "[ok] confirmed dbgp decision outcomes: " . implode(", ", $required) . PHP_EOL;
}
' "${REMOTE_VERIFIER_DIR}" "${XSS_BROWSER_MODE}" "${VALIDATE_XSS_BROWSER_REASON}" "${VALIDATE_XSS_BROWSER_EXECUTION_CONFIRMED}" "${XSS_BROWSER_ADVISORY_MAX_FAILURE_RATE}" "${XSS_BROWSER_ADVISORY_MAX_UNCONFIGURED_RATE}" "${MAX_DEAD_LETTERS}" "${CAPABILITY_ASSERTIONS_JSON}" "${STRICT_EXTENSION_PROFILE}" "${EXTENSION_PROFILE}" "${REMOTE_VERIFIER_DIR}/extension_assertions_summary.json" "${VERIFIER_BACKEND}"
REMOTE
then
  echo "[remote-verifier] Validation failed. Dumping verifier artifacts and logs..." >&2
  ssh_exec "${REMOTE_CMD}" <<'REMOTE'
set -euo pipefail

echo "--- verifier jobs ---"
cat "${REMOTE_VERIFIER_DIR}/jobs.jsonl" 2>/dev/null || true
echo "--- verifier results ---"
cat "${REMOTE_VERIFIER_DIR}/results.jsonl" 2>/dev/null || true
echo "--- verifier decisions ---"
cat "${REMOTE_VERIFIER_DIR}/decisions.jsonl" 2>/dev/null || true
echo "--- verifier dead letters ---"
cat "${REMOTE_VERIFIER_DIR}/dead_letters.jsonl" 2>/dev/null || true
echo "--- verifier claims ---"
cat "${REMOTE_VERIFIER_DIR}/claims.jsonl" 2>/dev/null || true
echo "--- verifier artifacts ---"
find "${REMOTE_VERIFIER_DIR}/artifacts" -maxdepth 3 -type f 2>/dev/null | while read -r f; do
  echo "## $f"
  cat "$f" || true
done
REMOTE
  exit 1
fi

echo "[remote-verifier] PASS: remote verifier pipeline (php_worker) confirmed RCE/SSRF/SQLi/File/XSS/IDOR/XXE coverage on ${HOST} with extension-profile assertions."
