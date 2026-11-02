#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SDK_DIR="${ROOT_DIR}/subprojects/nodejs_php_dbgp_client_sdk"
RUNTIME_DIR="${ROOT_DIR}/.php_taint_trace_runtime/verifier"
CANDIDATES_JSONL=""
DECISIONS_JSONL=""
DECISION_DIR=""
ARTIFACT_DIR=""

HOST="${PHP_TAINT_TRACE_DBGP_HOST:-127.0.0.1}"
PORT="${PHP_TAINT_TRACE_DBGP_PORT:-9003}"
TIMEOUT_MS="${PHP_TAINT_TRACE_DBGP_TIMEOUT_MS:-120000}"
ATTEMPTS="${PHP_TAINT_TRACE_DBGP_ATTEMPTS:-3}"
LIMIT="${PHP_TAINT_TRACE_DBGP_LIMIT:-200}"
CONCURRENCY="${PHP_TAINT_TRACE_DBGP_CONCURRENCY:-}"
SINK_CATEGORY="${PHP_TAINT_TRACE_DBGP_FALLBACK_SINK_CATEGORY:-rce}"
OUTPUT_MODE="${PHP_TAINT_TRACE_DBGP_OUTPUT_MODE:-json}"
NODE_BIN="${NODE_BIN:-node}"

TRIGGER_BASE_URL="${PHP_TAINT_TRACE_DBGP_TRIGGER_BASE_URL:-http://127.0.0.1}"
TRIGGER_HTTP_TIMEOUT="${PHP_TAINT_TRACE_DBGP_TRIGGER_HTTP_TIMEOUT:-10}"
TRIGGER_CMD_TEMPLATE=""

PORT_XSS="${PHP_TAINT_TRACE_DBGP_PORT_XSS:-19081}"
PORT_RCE="${PHP_TAINT_TRACE_DBGP_PORT_RCE:-19082}"
PORT_FILE="${PHP_TAINT_TRACE_DBGP_PORT_FILE:-19083}"
PORT_SSRF="${PHP_TAINT_TRACE_DBGP_PORT_SSRF:-19084}"
PORT_SQLI="${PHP_TAINT_TRACE_DBGP_PORT_SQLI:-19085}"
PORT_IDOR="${PHP_TAINT_TRACE_DBGP_PORT_IDOR:-19086}"
PORT_XXE="${PHP_TAINT_TRACE_DBGP_PORT_XXE:-19087}"
PORT_DEFAULT="${PHP_TAINT_TRACE_DBGP_PORT_DEFAULT:-19082}"
XDEBUG_TRIGGER_VALUE="${PHP_TAINT_TRACE_DBGP_XDEBUG_TRIGGER:-php-taint-trace}"

TRUNCATE_OUTPUT=0
FAIL_ON_UNCONFIRMED=0
STOP_ON_ERROR=0
STOP_ON_FIRST_SUCCESS=1
REQUIRE_REPLAY_EVIDENCE=1
DRY_RUN=0

usage() {
  cat <<'USAGE'
Usage: scripts/run_dbgp_verifier_batch.sh [options]

Run Node.js DBGp verifier batch mode directly against detector candidate/job JSONL.

Options:
  --runtime-dir PATH            Runtime root (default: .php_taint_trace_runtime/verifier)
  --candidates-jsonl PATH       Candidate/job JSONL input (default: <runtime>/jobs.jsonl)
  --decisions-jsonl PATH        Decision JSONL output (default: <runtime>/decisions_dbgp.jsonl)
  --decision-dir PATH           Optional per-candidate decision JSON directory (default: <runtime>/decisions_dbgp)
  --artifact-dir PATH           Artifact directory for replay attempts (default: <runtime>/artifacts/dbgp_batch)
  --sdk-dir PATH                SDK directory (default: subprojects/nodejs_php_dbgp_client_sdk)
  --node-bin BIN                Node.js executable (default: node)
  --host HOST                   DBGp listener host (default: 127.0.0.1)
  --port N                      DBGp listener port (default: 9003)
  --timeout-ms N                Session/command timeout ms (default: 30000)
  --attempts N                  Replay attempts per candidate (default: 3)
  --limit N                     Max candidates processed (default: 200)
  --concurrency N               Candidates processed in parallel per batch (default: CPU core count)
  --sink-category VALUE         Fallback sink category (default: rce)
  --output MODE                 CLI output mode: human|json (default: json)
  --trigger-base-url URL        Default trigger base URL when request_uri is relative (default: http://127.0.0.1)
  --trigger-http-timeout N      HTTP timeout seconds for trigger requests (default: 10)
  --trigger-cmd CMD             Custom trigger command template.
                                Supports ${candidateId}, ${sinkCategory}, ${sinkName}, ${requestUri},
                                ${correlationId}, ${requestId}, ${findingId}, ${traceId}, ${attempt}, ${attemptIndex}.
  --port-xss N                  Default lab port for xss category (default: 19081)
  --port-rce N                  Default lab port for rce category (default: 19082)
  --port-file N                 Default lab port for file category (default: 19083)
  --port-ssrf N                 Default lab port for ssrf category (default: 19084)
  --port-sqli N                 Default lab port for sqli category (default: 19085)
  --port-idor N                 Default lab port for idor category (default: 19086)
  --port-xxe N                  Default lab port for xxe category (default: 19087)
  --port-default N              Default fallback port when category is unknown (default: 19082)
  --truncate                    Truncate decisions output before writing.
  --fail-on-unconfirmed         Exit non-zero unless every decision is confirmed.
  --stop-on-error               Stop batch processing on first candidate error.
  --no-stop-on-first-success    Keep replaying attempts even after success.
  --no-require-replay-evidence  Allow success without replay evidence (advanced mode).
  --dry-run                     Print resolved command and exit without executing.
  -h, --help                    Show this help.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --runtime-dir)
      RUNTIME_DIR="$2"
      shift 2
      ;;
    --candidates-jsonl)
      CANDIDATES_JSONL="$2"
      shift 2
      ;;
    --decisions-jsonl)
      DECISIONS_JSONL="$2"
      shift 2
      ;;
    --decision-dir)
      DECISION_DIR="$2"
      shift 2
      ;;
    --artifact-dir)
      ARTIFACT_DIR="$2"
      shift 2
      ;;
    --sdk-dir)
      SDK_DIR="$2"
      shift 2
      ;;
    --node-bin)
      NODE_BIN="$2"
      shift 2
      ;;
    --host)
      HOST="$2"
      shift 2
      ;;
    --port)
      PORT="$2"
      shift 2
      ;;
    --timeout-ms)
      TIMEOUT_MS="$2"
      shift 2
      ;;
    --attempts)
      ATTEMPTS="$2"
      shift 2
      ;;
    --limit)
      LIMIT="$2"
      shift 2
      ;;
    --concurrency)
      CONCURRENCY="$2"
      shift 2
      ;;
    --sink-category)
      SINK_CATEGORY="$2"
      shift 2
      ;;
    --output)
      OUTPUT_MODE="$2"
      shift 2
      ;;
    --trigger-base-url)
      TRIGGER_BASE_URL="$2"
      shift 2
      ;;
    --trigger-http-timeout)
      TRIGGER_HTTP_TIMEOUT="$2"
      shift 2
      ;;
    --trigger-cmd)
      TRIGGER_CMD_TEMPLATE="$2"
      shift 2
      ;;
    --port-xss)
      PORT_XSS="$2"
      shift 2
      ;;
    --port-rce)
      PORT_RCE="$2"
      shift 2
      ;;
    --port-file)
      PORT_FILE="$2"
      shift 2
      ;;
    --port-ssrf)
      PORT_SSRF="$2"
      shift 2
      ;;
    --port-sqli)
      PORT_SQLI="$2"
      shift 2
      ;;
    --port-idor)
      PORT_IDOR="$2"
      shift 2
      ;;
    --port-xxe)
      PORT_XXE="$2"
      shift 2
      ;;
    --port-default)
      PORT_DEFAULT="$2"
      shift 2
      ;;
    --truncate)
      TRUNCATE_OUTPUT=1
      shift
      ;;
    --fail-on-unconfirmed)
      FAIL_ON_UNCONFIRMED=1
      shift
      ;;
    --stop-on-error)
      STOP_ON_ERROR=1
      shift
      ;;
    --no-stop-on-first-success)
      STOP_ON_FIRST_SUCCESS=0
      shift
      ;;
    --no-require-replay-evidence)
      REQUIRE_REPLAY_EVIDENCE=0
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
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

if [[ -z "${CANDIDATES_JSONL}" ]]; then
  CANDIDATES_JSONL="${RUNTIME_DIR}/jobs.jsonl"
fi
if [[ -z "${DECISIONS_JSONL}" ]]; then
  DECISIONS_JSONL="${RUNTIME_DIR}/decisions_dbgp.jsonl"
fi
if [[ -z "${DECISION_DIR}" ]]; then
  DECISION_DIR="${RUNTIME_DIR}/decisions_dbgp"
fi
if [[ -z "${ARTIFACT_DIR}" ]]; then
  ARTIFACT_DIR="${RUNTIME_DIR}/artifacts/dbgp_batch"
fi

if [[ ! -d "${SDK_DIR}" ]]; then
  echo "SDK directory not found: ${SDK_DIR}" >&2
  exit 1
fi

TSX_CLI="${SDK_DIR}/node_modules/tsx/dist/cli.mjs"
if [[ ! -f "${TSX_CLI}" ]]; then
  echo "Missing tsx CLI at ${TSX_CLI}" >&2
  echo "Install SDK dependencies first: (cd ${SDK_DIR} && npm install)" >&2
  exit 1
fi

if [[ ! -f "${CANDIDATES_JSONL}" ]]; then
  echo "Candidates JSONL not found: ${CANDIDATES_JSONL}" >&2
  exit 1
fi

if [[ -z "${TRIGGER_CMD_TEMPLATE}" ]]; then
  TRIGGER_CMD_TEMPLATE='php -r '"'"'
$uri = (string) ($argv[1] ?? "");
$category = strtolower((string) ($argv[2] ?? ""));
$baseUrl = getenv("PHP_TAINT_TRACE_DBGP_TRIGGER_BASE_URL");
if (!is_string($baseUrl) || $baseUrl === "") {
    $baseUrl = "http://127.0.0.1";
}
$portMap = array(
    "xss" => (string) (getenv("PHP_TAINT_TRACE_DBGP_PORT_XSS") ?: "19081"),
    "rce" => (string) (getenv("PHP_TAINT_TRACE_DBGP_PORT_RCE") ?: "19082"),
    "file" => (string) (getenv("PHP_TAINT_TRACE_DBGP_PORT_FILE") ?: "19083"),
    "ssrf" => (string) (getenv("PHP_TAINT_TRACE_DBGP_PORT_SSRF") ?: "19084"),
    "sqli" => (string) (getenv("PHP_TAINT_TRACE_DBGP_PORT_SQLI") ?: "19085"),
    "idor" => (string) (getenv("PHP_TAINT_TRACE_DBGP_PORT_IDOR") ?: "19086"),
    "xxe" => (string) (getenv("PHP_TAINT_TRACE_DBGP_PORT_XXE") ?: "19087"),
);
$defaultPort = (string) (getenv("PHP_TAINT_TRACE_DBGP_PORT_DEFAULT") ?: "19082");
$prefix = rtrim($baseUrl, "/");
if (preg_match("/:[0-9]+$/", $prefix) !== 1) {
    $prefix .= ":" . ($portMap[$category] ?? $defaultPort);
}
if ($uri === "") {
    $uri = "/";
}
if (preg_match("/^https?:\\/\\//i", $uri) === 1) {
    $url = $uri;
} else {
    if ($uri[0] !== "/") {
        $uri = "/" . $uri;
    }
    $url = $prefix . $uri;
}
$xdebugTrigger = (string) (getenv("PHP_TAINT_TRACE_DBGP_XDEBUG_TRIGGER") ?: "php-taint-trace");
$url .= (str_contains($url, "?") ? "&" : "?") . "XDEBUG_TRIGGER=" . rawurlencode($xdebugTrigger);
$httpTimeout = (int) (getenv("PHP_TAINT_TRACE_DBGP_TRIGGER_HTTP_TIMEOUT") ?: "10");
if ($httpTimeout < 1) {
    $httpTimeout = 1;
}
$ctx = stream_context_create(array(
    "http" => array(
        "ignore_errors" => true,
        "timeout" => $httpTimeout,
    ),
));
@file_get_contents($url, false, $ctx);
'"'"' -- ${requestUri} ${sinkCategory}'
fi

if [[ -z "${CONCURRENCY}" ]]; then
  if command -v nproc >/dev/null 2>&1; then
    CONCURRENCY="$(nproc)"
  elif command -v getconf >/dev/null 2>&1; then
    CONCURRENCY="$(getconf _NPROCESSORS_ONLN 2>/dev/null || true)"
  fi
fi

if [[ -z "${CONCURRENCY}" ]]; then
  CONCURRENCY=1
fi

if ! [[ "${CONCURRENCY}" =~ ^[0-9]+$ ]] || [[ "${CONCURRENCY}" -lt 1 ]]; then
  echo "Invalid --concurrency: ${CONCURRENCY}. Expected positive integer." >&2
  exit 1
fi
if ! [[ "${TRIGGER_HTTP_TIMEOUT}" =~ ^[0-9]+$ ]] || [[ "${TRIGGER_HTTP_TIMEOUT}" -lt 1 ]]; then
  echo "Invalid --trigger-http-timeout: ${TRIGGER_HTTP_TIMEOUT}. Expected positive integer (seconds)." >&2
  exit 1
fi

mkdir -p "$(dirname "${DECISIONS_JSONL}")" "${DECISION_DIR}" "${ARTIFACT_DIR}"

export PHP_TAINT_TRACE_DBGP_TRIGGER_BASE_URL="${TRIGGER_BASE_URL}"
export PHP_TAINT_TRACE_DBGP_PORT_XSS="${PORT_XSS}"
export PHP_TAINT_TRACE_DBGP_PORT_RCE="${PORT_RCE}"
export PHP_TAINT_TRACE_DBGP_PORT_FILE="${PORT_FILE}"
export PHP_TAINT_TRACE_DBGP_PORT_SSRF="${PORT_SSRF}"
export PHP_TAINT_TRACE_DBGP_PORT_SQLI="${PORT_SQLI}"
export PHP_TAINT_TRACE_DBGP_PORT_IDOR="${PORT_IDOR}"
export PHP_TAINT_TRACE_DBGP_PORT_XXE="${PORT_XXE}"
export PHP_TAINT_TRACE_DBGP_PORT_DEFAULT="${PORT_DEFAULT}"
export PHP_TAINT_TRACE_DBGP_XDEBUG_TRIGGER="${XDEBUG_TRIGGER_VALUE}"
export PHP_TAINT_TRACE_DBGP_TRIGGER_HTTP_TIMEOUT="${TRIGGER_HTTP_TIMEOUT}"

CMD=(
  "${NODE_BIN}"
  "${TSX_CLI}"
  "${SDK_DIR}/src/cli.ts"
  verifier-decision-batch
  --host "${HOST}"
  --port "${PORT}"
  --timeout-ms "${TIMEOUT_MS}"
  --candidates-jsonl "${CANDIDATES_JSONL}"
  --decisions-jsonl "${DECISIONS_JSONL}"
  --decision-dir "${DECISION_DIR}"
  --artifact-dir "${ARTIFACT_DIR}"
  --attempts "${ATTEMPTS}"
  --limit "${LIMIT}"
  --concurrency "${CONCURRENCY}"
  --sink-category "${SINK_CATEGORY}"
  --output "${OUTPUT_MODE}"
  --trigger-cmd "${TRIGGER_CMD_TEMPLATE}"
)

if [[ "${TRUNCATE_OUTPUT}" -eq 1 ]]; then
  CMD+=(--truncate-decisions-jsonl)
fi
if [[ "${FAIL_ON_UNCONFIRMED}" -eq 1 ]]; then
  CMD+=(--fail-on-unconfirmed)
fi
if [[ "${STOP_ON_ERROR}" -eq 1 ]]; then
  CMD+=(--stop-on-error)
fi
if [[ "${STOP_ON_FIRST_SUCCESS}" -eq 0 ]]; then
  CMD+=(--no-stop-on-first-success)
fi
if [[ "${REQUIRE_REPLAY_EVIDENCE}" -eq 0 ]]; then
  CMD+=(--no-require-replay-evidence)
fi

if [[ "${DRY_RUN}" -eq 1 ]]; then
  echo "[dbgp-batch] dry-run command:"
  printf ' %q' "${CMD[@]}"
  printf '\n'
  exit 0
fi

echo "[dbgp-batch] runtime_dir=${RUNTIME_DIR}"
echo "[dbgp-batch] candidates=${CANDIDATES_JSONL}"
echo "[dbgp-batch] decisions=${DECISIONS_JSONL}"
echo "[dbgp-batch] decision_dir=${DECISION_DIR}"
echo "[dbgp-batch] artifact_dir=${ARTIFACT_DIR}"
echo "[dbgp-batch] trigger_base_url=${TRIGGER_BASE_URL}"
echo "[dbgp-batch] trigger_http_timeout=${TRIGGER_HTTP_TIMEOUT}"
echo "[dbgp-batch] listener=${HOST}:${PORT}"
echo "[dbgp-batch] concurrency=${CONCURRENCY}"

"${CMD[@]}"
