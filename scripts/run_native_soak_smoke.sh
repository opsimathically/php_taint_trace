#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXT_PATH="${ROOT_DIR}/ext/xmark/modules/xmark.so"
PREPEND_PATH="${ROOT_DIR}/scripts/auto_prepend.php"
APP_DOCROOT="${ROOT_DIR}/tests/fixtures/unmodified_app/public"
EXTRA_PHP_ARGS_RAW="${PHP_TAINT_TRACE_SOAK_EXTRA_PHP_ARGS:-}"
EXTRA_PHP_ARGS=()

if [[ -n "${EXTRA_PHP_ARGS_RAW}" ]]; then
  # shellcheck disable=SC2206
  EXTRA_PHP_ARGS=(${EXTRA_PHP_ARGS_RAW})
fi

REQUESTS="${PHP_TAINT_TRACE_SOAK_REQUESTS:-200}"
CONCURRENCY="${PHP_TAINT_TRACE_SOAK_CONCURRENCY:-16}"

if ! [[ "${REQUESTS}" =~ ^[0-9]+$ ]] || [[ "${REQUESTS}" -lt 1 ]]; then
  echo "Invalid PHP_TAINT_TRACE_SOAK_REQUESTS: ${REQUESTS}" >&2
  exit 1
fi

if ! [[ "${CONCURRENCY}" =~ ^[0-9]+$ ]] || [[ "${CONCURRENCY}" -lt 1 ]]; then
  echo "Invalid PHP_TAINT_TRACE_SOAK_CONCURRENCY: ${CONCURRENCY}" >&2
  exit 1
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
  echo "Missing soak app docroot at ${APP_DOCROOT}" >&2
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "curl not found. Install curl to run native soak smoke." >&2
  exit 1
fi

TMP_DIR="$(mktemp -d)"
FINDINGS_PATH="${TMP_DIR}/findings.jsonl"
SERVER_LOG="${TMP_DIR}/server.log"
REQUEST_FAILURES_PATH="${TMP_DIR}/request_failures.log"
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

: > "${REQUEST_FAILURES_PATH}"

seq 1 "${REQUESTS}" | xargs -P "${CONCURRENCY}" -I{} bash -c '
request_id="$1"
base_url="$2"
url="${base_url}?name=xtanzi-${request_id}"
if ! body="$(curl --silent --show-error --fail --max-time 10 "${url}")"; then
  echo "${request_id}" >> "$3"
  exit 1
fi
if [[ "${body}" != *"Hello "* ]]; then
  echo "${request_id}" >> "$3"
  exit 1
fi
' _ {} "http://127.0.0.1:${PORT}/" "${REQUEST_FAILURES_PATH}" || true

if [[ -s "${REQUEST_FAILURES_PATH}" ]]; then
  echo "Soak request failures detected." >&2
  echo "--- failed request ids ---" >&2
  cat "${REQUEST_FAILURES_PATH}" >&2 || true
  echo "--- server log ---" >&2
  cat "${SERVER_LOG}" >&2 || true
  exit 1
fi

EXPECTED_MIN="${REQUESTS}"
FOUND=0
DETECTED_COUNT=0

for _ in $(seq 1 80); do
  if [[ -s "${FINDINGS_PATH}" ]]; then
    DETECTED_COUNT="$(php -r '
$path = $argv[1];
$count = 0;
$lines = @file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
if (!is_array($lines)) {
    echo "0";
    exit(0);
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
            $count++;
        }
    }
}
echo $count;
' "${FINDINGS_PATH}")"
    if [[ "${DETECTED_COUNT}" -ge "${EXPECTED_MIN}" ]]; then
      FOUND=1
      break
    fi
  fi
  sleep 0.1
done

if [[ ${FOUND} -ne 1 ]]; then
  echo "Soak check failed: printf/xss findings below expected minimum." >&2
  echo "Expected at least: ${EXPECTED_MIN}" >&2
  echo "Observed: ${DETECTED_COUNT}" >&2
  if [[ -f "${FINDINGS_PATH}" ]]; then
    echo "--- findings ---" >&2
    cat "${FINDINGS_PATH}" >&2 || true
  fi
  echo "--- server log ---" >&2
  cat "${SERVER_LOG}" >&2 || true
  exit 1
fi

if grep -Eiq 'Fatal error|Segmentation fault|core dumped|zend_mm_heap corrupted' "${SERVER_LOG}"; then
  echo "Soak check failed: fatal/runtime corruption markers found in server log." >&2
  echo "--- server log ---" >&2
  cat "${SERVER_LOG}" >&2 || true
  exit 1
fi

echo "Native soak smoke passed. Requests=${REQUESTS} Concurrency=${CONCURRENCY} Findings=${DETECTED_COUNT}"
