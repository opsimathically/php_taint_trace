#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_PATH="${PHP_TAINT_TRACE_TEST_CONFIG:-${XDG_CONFIG_HOME:-${HOME}/.config}/php_taint_trace/testing_container_config.json}"
HOST_LABEL="${PHP_TAINT_TRACE_TEST_HOST_LABEL:-lab.example.invalid}"
REMOTE_ROOT="/opt/php_taint_trace_vuln_lab"
EXTENSION_PROFILE="${PHP_TAINT_TRACE_REMOTE_EXTENSION_PROFILE:-base}"
STRICT_EXTENSION_PROFILE=0

usage() {
  cat <<'USAGE'
Usage: scripts/run_remote_vuln_lab_tests.sh [--config PATH] [--host-label LABEL] [--remote-root PATH]
                                      [--extension-profile base|extended_sql|extended_rce|extended_all]
                                      [--strict-extension-profile]

Runs end-to-end remote vulnerable app tests and asserts expected taint findings.
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

REMOTE_CMD="$(printf "REMOTE_PROJECT_ROOT=%q EXTENSION_PROFILE=%q bash -s" "${REMOTE_PROJECT_ROOT}" "${EXTENSION_PROFILE}")"
REMOTE_VALIDATE_CMD=""

echo "[remote-test] Restarting vulnerable app lab and clearing findings"
ssh_exec "${REMOTE_CMD}" <<'REMOTE'
set -euo pipefail

export PHP_TAINT_TRACE_ENABLE_OPCODE_HOOKS=1
export PHP_TAINT_TRACE_OPCODE_HOOK_PROFILE=safe
export PHP_TAINT_TRACE_LAB_EXTENSION_PROFILE="${EXTENSION_PROFILE}"
cd "${REMOTE_PROJECT_ROOT}"
bash scripts/remote_vuln_lab_manage.sh profile "${EXTENSION_PROFILE}"
bash scripts/remote_vuln_lab_manage.sh restart
bash scripts/remote_vuln_lab_manage.sh reset
REMOTE

echo "[remote-test] Collecting remote capability snapshot"
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
  "REMOTE_PROJECT_ROOT=%q EXTENSION_PROFILE=%q CAPABILITY_ASSERTIONS_JSON=%q STRICT_EXTENSION_PROFILE=%q bash -s" \
  "${REMOTE_PROJECT_ROOT}" \
  "${EXTENSION_PROFILE}" \
  "${CAPABILITY_ASSERTIONS_JSON}" \
  "${STRICT_EXTENSION_PROFILE}" \
)"

echo "[remote-test] Extension profile: ${EXTENSION_PROFILE} (strict=${STRICT_EXTENSION_PROFILE})"

echo "[remote-test] Triggering vulnerable app requests"
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

http_expect_contains() {
  php -r '
$url = $argv[1];
$needle = $argv[2];
$ctx = stream_context_create(array(
    "http" => array(
        "ignore_errors" => true,
        "timeout" => 4,
    ),
));
$body = @file_get_contents($url, false, $ctx);
if (!is_string($body)) {
    fwrite(STDERR, "request failed: " . $url . PHP_EOL);
    exit(1);
}
if (!str_contains($body, $needle)) {
    fwrite(STDERR, "response missing expected marker: " . $needle . " for " . $url . PHP_EOL);
    exit(1);
}
' "$1" "$2"
}

http_get 'http://127.0.0.1:19081/?name=%3Cscript%3Extanzi%3C%2Fscript%3E'
http_get 'http://127.0.0.1:19082/?cmd=echo%20xtanzi'
http_get 'http://127.0.0.1:19082/?sink=mail&cmd=-X%20%2Ftmp%2Fxtanzi'
http_get 'http://127.0.0.1:19082/?sink=exec&cmd=echo%20xtanzi'
http_get 'http://127.0.0.1:19082/?sink=shell_exec&cmd=echo%20xtanzi'
http_get 'http://127.0.0.1:19082/?sink=popen&cmd=echo%20xtanzi'
http_get 'http://127.0.0.1:19082/?sink=passthru&cmd=echo%20xtanzi'
http_get 'http://127.0.0.1:19082/?sink=proc_open&cmd=echo%20xtanzi'
http_get 'http://127.0.0.1:19082/?sink=unserialize_template&cmd=echo%20xtanzi'
http_get 'http://127.0.0.1:19082/?sink=eval&cmd=echo%20%22xtanzi%22%3B'
http_get 'http://127.0.0.1:19083/?path=%2Fetc%2Fhostname'
http_get 'http://127.0.0.1:19083/?sink=splfileobject&path=%2Fetc%2Fhostname'
http_get 'http://127.0.0.1:19083/?sink=fopen&path=%2Fetc%2Fhostname'
http_get 'http://127.0.0.1:19083/?sink=readfile&path=%2Fetc%2Fhostname'
http_get 'http://127.0.0.1:19084/?url=http%3A%2F%2F127.0.0.1%3A19081%2F%3Fname%3Dxtanzi'
http_get 'http://127.0.0.1:19084/?sink=stream_socket_client&url=http%3A%2F%2F127.0.0.1%3A19081%2F%3Fname%3Dxtanzi'
http_get 'http://127.0.0.1:19084/?sink=pfsockopen&url=http%3A%2F%2F127.0.0.1%3A19081%2F%3Fname%3Dxtanzi'
http_get 'http://127.0.0.1:19084/?sink=curl_setopt&url=http%3A%2F%2F127.0.0.1%3A19081%2F%3Fname%3Dxtanzi'
http_get 'http://127.0.0.1:19084/?sink=curl_setopt_array&url=http%3A%2F%2F127.0.0.1%3A19081%2F%3Fname%3Dxtanzi'
http_get 'http://127.0.0.1:19084/?sink=curl_multi_setopt&url=http%3A%2F%2F127.0.0.1%3A19081%2F%3Fname%3Dxtanzi'
http_get 'http://127.0.0.1:19084/?sink=curl_multi_setopt_array&url=http%3A%2F%2F127.0.0.1%3A19081%2F%3Fname%3Dxtanzi'
http_get 'http://127.0.0.1:19084/?sink=fsockopen&url=http%3A%2F%2F127.0.0.1%3A19081%2F%3Fname%3Dxtanzi'
http_get 'http://127.0.0.1:19084/?sink=get_headers&url=http%3A%2F%2F127.0.0.1%3A19081%2F%3Fname%3Dxtanzi'
http_get 'http://127.0.0.1:19084/?sink=soapclient_construct&url=http%3A%2F%2F127.0.0.1%3A19081%2F%3Fname%3Dxtanzi'
http_get 'http://127.0.0.1:19084/?sink=soapclient_location&url=http%3A%2F%2F127.0.0.1%3A19081%2F%3Fname%3Dxtanzi'
http_get 'http://127.0.0.1:19084/?sink=soapclient_setlocation&url=http%3A%2F%2F127.0.0.1%3A19081%2F%3Fname%3Dxtanzi'
http_expect_contains 'http://127.0.0.1:19085/?q=SELECT%20username%20FROM%20users%20WHERE%20id%20%3D%201' 'alice'
http_get 'http://127.0.0.1:19086/?resource_id=42&actor_id=1043&mode=vuln'
http_get 'http://127.0.0.1:19087/?xml=%3C!DOCTYPE%20root%20%5B%3C!ENTITY%20xxe%20SYSTEM%20%22http%3A%2F%2F127.0.0.1%3A19081%2F%3Fname%3Dxtanzi%22%3E%5D%3E%3Croot%3E%26xxe%3B%3C%2Froot%3E'
http_get 'http://127.0.0.1:19087/?sink=dom_load&xml=%3C!DOCTYPE%20root%20%5B%3C!ENTITY%20xxe%20SYSTEM%20%22http%3A%2F%2F127.0.0.1%3A19081%2F%3Fname%3Dxtanzi%22%3E%5D%3E%3Croot%3E%26xxe%3B%3C%2Froot%3E'
http_get 'http://127.0.0.1:19087/?sink=dom_loadxml&xml=%3C!DOCTYPE%20root%20%5B%3C!ENTITY%20xxe%20SYSTEM%20%22http%3A%2F%2F127.0.0.1%3A19081%2F%3Fname%3Dxtanzi%22%3E%5D%3E%3Croot%3E%26xxe%3B%3C%2Froot%3E'
http_get 'http://127.0.0.1:19087/?sink=xmlreader_open&xml=%3C!DOCTYPE%20root%20%5B%3C!ENTITY%20xxe%20SYSTEM%20%22http%3A%2F%2F127.0.0.1%3A19081%2F%3Fname%3Dxtanzi%22%3E%5D%3E%3Croot%3E%26xxe%3B%3C%2Froot%3E'
http_get 'http://127.0.0.1:19087/?sink=xmlreader_xml&xml=%3C!DOCTYPE%20root%20%5B%3C!ENTITY%20xxe%20SYSTEM%20%22http%3A%2F%2F127.0.0.1%3A19081%2F%3Fname%3Dxtanzi%22%3E%5D%3E%3Croot%3E%26xxe%3B%3C%2Froot%3E'
http_get 'http://127.0.0.1:19087/?sink=simplexml&xml=%3C!DOCTYPE%20root%20%5B%3C!ENTITY%20xxe%20SYSTEM%20%22http%3A%2F%2F127.0.0.1%3A19081%2F%3Fname%3Dxtanzi%22%3E%5D%3E%3Croot%3E%26xxe%3B%3C%2Froot%3E'
http_get 'http://127.0.0.1:19087/?sink=simplexml_file&xml=%3C!DOCTYPE%20root%20%5B%3C!ENTITY%20xxe%20SYSTEM%20%22http%3A%2F%2F127.0.0.1%3A19081%2F%3Fname%3Dxtanzi%22%3E%5D%3E%3Croot%3E%26xxe%3B%3C%2Froot%3E'
http_get 'http://127.0.0.1:19082/?sink=pcntl_exec&cmd=%2Fdefinitely%2Fnot%2Ffound_xtanzi'
http_get 'http://127.0.0.1:19082/?sink=expect_popen&cmd=echo%20xtanzi'
http_get 'http://127.0.0.1:19082/?sink=dl&cmd=nonexistent_xtanzi_extension'
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

echo "[remote-test] Validating findings"
if ! ssh_exec "${REMOTE_VALIDATE_CMD}" <<'REMOTE'
set -euo pipefail

php -r '
$base = $argv[1] . "/.remote_vuln_lab_runtime/findings";
$capabilityPayload = json_decode((string) ($argv[2] ?? "{}"), true);
$strictExtensionProfile = filter_var((string) ($argv[3] ?? "0"), FILTER_VALIDATE_BOOL);
$requestedProfile = strtolower(trim((string) ($argv[4] ?? "base")));
$summaryPath = (string) ($argv[5] ?? "");
$checks = array(
    "xss_app" => array("path" => $base . "/xss_app.jsonl", "sink" => "printf", "category" => "xss"),
    "rce_app" => array("path" => $base . "/rce_app.jsonl", "sink" => "system", "category" => "rce"),
    "rce_app_mail" => array("path" => $base . "/rce_app.jsonl", "sink" => "mail", "category" => "rce"),
    "file_app" => array("path" => $base . "/file_app.jsonl", "sink" => "file_get_contents", "category" => "file"),
    "file_app_spl" => array("path" => $base . "/file_app.jsonl", "sink" => "SplFileObject::__construct", "category" => "file"),
    "ssrf_app" => array("path" => $base . "/ssrf_app.jsonl", "sink" => "file_get_contents", "category" => "ssrf"),
    "ssrf_app_stream_socket_client" => array("path" => $base . "/ssrf_app.jsonl", "sink" => "stream_socket_client", "category" => "ssrf"),
    "ssrf_app_pfsockopen" => array("path" => $base . "/ssrf_app.jsonl", "sink" => "pfsockopen", "category" => "ssrf"),
    "sqli_app" => array("path" => $base . "/sqli_app.jsonl", "sinks" => array("PDO::query", "mysqli_query"), "category" => "sqli"),
    "idor_app" => array("path" => $base . "/idor_app.jsonl", "sink" => "printf", "category" => "xss"),
    "xxe_app" => array("path" => $base . "/xxe_app.jsonl", "sink" => "simplexml_load_string", "category" => "xxe"),
);
$optionalChecks = array(
    "rce_exec" => array("path" => $base . "/rce_app.jsonl", "sink" => "exec", "category" => "rce", "request_uri_contains" => "sink=exec"),
    "rce_shell_exec" => array("path" => $base . "/rce_app.jsonl", "sink" => "shell_exec", "category" => "rce", "request_uri_contains" => "sink=shell_exec"),
    "rce_popen" => array("path" => $base . "/rce_app.jsonl", "sink" => "popen", "category" => "rce", "request_uri_contains" => "sink=popen"),
    "rce_passthru" => array("path" => $base . "/rce_app.jsonl", "sink" => "passthru", "category" => "rce", "request_uri_contains" => "sink=passthru"),
    "rce_proc_open" => array("path" => $base . "/rce_app.jsonl", "sink" => "proc_open", "category" => "rce", "request_uri_contains" => "sink=proc_open"),
    "rce_unserialize_template" => array("path" => $base . "/rce_app.jsonl", "sink" => "unserialize", "category" => "rce", "request_uri_contains" => "sink=unserialize_template"),
    "rce_include_or_eval" => array("path" => $base . "/rce_app.jsonl", "sink" => "include_or_eval", "category" => "rce", "request_uri_contains" => "sink=eval"),
    "rce_pcntl_exec" => array("path" => $base . "/rce_app.jsonl", "sink" => "pcntl_exec", "category" => "rce", "request_uri_contains" => "sink=pcntl_exec"),
    "rce_expect_popen" => array("path" => $base . "/rce_app.jsonl", "sink" => "expect_popen", "category" => "rce", "request_uri_contains" => "sink=expect_popen"),
    "rce_dl" => array("path" => $base . "/rce_app.jsonl", "sink" => "dl", "category" => "rce", "request_uri_contains" => "sink=dl"),
    "file_fopen" => array("path" => $base . "/file_app.jsonl", "sink" => "fopen", "category" => "file", "request_uri_contains" => "sink=fopen"),
    "file_readfile" => array("path" => $base . "/file_app.jsonl", "sink" => "readfile", "category" => "file", "request_uri_contains" => "sink=readfile"),
    "ssrf_curl_setopt" => array("path" => $base . "/ssrf_app.jsonl", "sink" => "curl_exec", "category" => "ssrf", "request_uri_contains" => "sink=curl_setopt"),
    "ssrf_curl_setopt_array" => array("path" => $base . "/ssrf_app.jsonl", "sink" => "curl_exec", "category" => "ssrf", "request_uri_contains" => "sink=curl_setopt_array"),
    "ssrf_curl_multi_setopt" => array("path" => $base . "/ssrf_app.jsonl", "sink" => "curl_multi_exec", "category" => "ssrf", "request_uri_contains" => "sink=curl_multi_setopt"),
    "ssrf_curl_multi_setopt_array" => array("path" => $base . "/ssrf_app.jsonl", "sink" => "curl_multi_exec", "category" => "ssrf", "request_uri_contains" => "sink=curl_multi_setopt_array"),
    "ssrf_fsockopen" => array("path" => $base . "/ssrf_app.jsonl", "sink" => "fsockopen", "category" => "ssrf", "request_uri_contains" => "sink=fsockopen"),
    "ssrf_get_headers" => array("path" => $base . "/ssrf_app.jsonl", "sink" => "get_headers", "category" => "ssrf", "request_uri_contains" => "sink=get_headers"),
    "ssrf_soapclient_construct" => array("path" => $base . "/ssrf_app.jsonl", "sink" => "SoapClient::__construct", "category" => "ssrf", "request_uri_contains" => "sink=soapclient_construct"),
    "ssrf_soapclient_location" => array("path" => $base . "/ssrf_app.jsonl", "sink" => "SoapClient::__construct", "category" => "ssrf", "request_uri_contains" => "sink=soapclient_location"),
    "ssrf_soapclient_setlocation" => array("path" => $base . "/ssrf_app.jsonl", "sink" => "SoapClient::__setLocation", "category" => "ssrf", "request_uri_contains" => "sink=soapclient_setlocation"),
    "sqli_pg_prepare" => array("path" => $base . "/sqli_app.jsonl", "sink" => "pg_prepare", "category" => "sqli", "request_uri_contains" => "sink=pg_prepare"),
    "sqli_pg_execute" => array("path" => $base . "/sqli_app.jsonl", "sink" => "pg_execute", "category" => "sqli", "request_uri_contains" => "sink=pg_execute"),
    "sqli_pg_send_execute" => array("path" => $base . "/sqli_app.jsonl", "sink" => "pg_send_execute", "category" => "sqli", "request_uri_contains" => "sink=pg_send_execute"),
    "sqli_pdo_query" => array("path" => $base . "/sqli_app.jsonl", "sink" => "PDO::query", "category" => "sqli", "request_uri_contains" => "sink=pdo_query"),
    "sqli_pdo_exec" => array("path" => $base . "/sqli_app.jsonl", "sink" => "PDO::exec", "category" => "sqli", "request_uri_contains" => "sink=pdo_exec"),
    "sqli_sqlite3_querysingle" => array("path" => $base . "/sqli_app.jsonl", "sink" => "SQLite3::querySingle", "category" => "sqli", "request_uri_contains" => "sink=sqlite3_querysingle"),
    "sqli_sqlite3_query" => array("path" => $base . "/sqli_app.jsonl", "sink" => "SQLite3::query", "category" => "sqli", "request_uri_contains" => "sink=sqlite3_query"),
    "sqli_sqlite3_exec" => array("path" => $base . "/sqli_app.jsonl", "sink" => "SQLite3::exec", "category" => "sqli", "request_uri_contains" => "sink=sqlite3_exec"),
    "sqli_mysqli_execute_query" => array("path" => $base . "/sqli_app.jsonl", "sink" => "mysqli_execute_query", "category" => "sqli", "request_uri_contains" => "sink=mysqli_execute_query"),
    "sqli_sqlsrv_prepare" => array("path" => $base . "/sqli_app.jsonl", "sink" => "sqlsrv_prepare", "category" => "sqli", "request_uri_contains" => "sink=sqlsrv_prepare"),
    "sqli_sqlsrv_query" => array("path" => $base . "/sqli_app.jsonl", "sink" => "sqlsrv_query", "category" => "sqli", "request_uri_contains" => "sink=sqlsrv_query"),
    "sqli_oci_parse" => array("path" => $base . "/sqli_app.jsonl", "sink" => "oci_parse", "category" => "sqli", "request_uri_contains" => "sink=oci_parse"),
    "xxe_domdocument_load" => array("path" => $base . "/xxe_app.jsonl", "sink" => "DOMDocument::load", "category" => "xxe", "request_uri_contains" => "sink=dom_load"),
    "xxe_domdocument_loadxml" => array("path" => $base . "/xxe_app.jsonl", "sink" => "DOMDocument::loadXML", "category" => "xxe", "request_uri_contains" => "sink=dom_loadxml"),
    "xxe_xmlreader_open" => array("path" => $base . "/xxe_app.jsonl", "sink" => "XMLReader::open", "category" => "xxe", "request_uri_contains" => "sink=xmlreader_open"),
    "xxe_xmlreader_xml" => array("path" => $base . "/xxe_app.jsonl", "sink" => "XMLReader::XML", "category" => "xxe", "request_uri_contains" => "sink=xmlreader_xml"),
    "xxe_simplexml_load_string" => array("path" => $base . "/xxe_app.jsonl", "sink" => "simplexml_load_string", "category" => "xxe", "request_uri_contains" => "sink=simplexml"),
    "xxe_simplexml_load_file" => array("path" => $base . "/xxe_app.jsonl", "sink" => "simplexml_load_file", "category" => "xxe", "request_uri_contains" => "sink=simplexml_file"),
);

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

$missing = array();

foreach ($checks as $app => $check) {
    $path = $check["path"];
    $sinks = array();
    if (isset($check["sinks"]) && is_array($check["sinks"])) {
        $sinks = array_map(static fn ($value) => (string) $value, $check["sinks"]);
    } elseif (isset($check["sink"])) {
        $sinks = array((string) $check["sink"]);
    }
    $category = $check["category"];

    $lines = @file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (!is_array($lines)) {
        $missing[] = $app . ": findings file missing or unreadable (" . $path . ")";
        continue;
    }

    $found = false;
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

            if (in_array((string) ($finding["sink_name"] ?? ""), $sinks, true) && ($finding["sink_category"] ?? null) === $category) {
                $found = true;
                break 2;
            }
        }
    }

    if ($found) {
        echo "[ok] " . $app . " => " . implode("|", $sinks) . "/" . $category . PHP_EOL;
        continue;
    }

    $missing[] = $app . ": expected finding " . implode("|", $sinks) . "/" . $category . " not found in " . $path;
}

$optionalExecuted = 0;
$optionalSkipped = 0;
foreach ($optionalChecks as $assertion => $check) {
    $available = (bool) ($capabilityAssertions[$assertion] ?? false);
    if (!$available) {
        $optionalSkipped++;
        echo "[skip] " . $assertion . " => capability unavailable" . PHP_EOL;
        if ($strictExtensionProfile && in_array($assertion, $requiredByProfile, true)) {
            $missing[] = $assertion . ": strict extension profile requires capability but it is unavailable";
        }
        continue;
    }

    $optionalExecuted++;
    $path = $check["path"];
    $sink = (string) $check["sink"];
    $category = (string) $check["category"];
    $requestUriContains = isset($check["request_uri_contains"]) && is_scalar($check["request_uri_contains"])
        ? (string) $check["request_uri_contains"]
        : "";
    $lines = @file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (!is_array($lines)) {
        $missing[] = $assertion . ": findings file missing or unreadable (" . $path . ")";
        continue;
    }

    $found = false;
    foreach ($lines as $line) {
        $payload = json_decode($line, true);
        if (!is_array($payload)) {
            continue;
        }

        if ($requestUriContains !== "") {
            $requestUri = is_scalar($payload["request_uri"] ?? null) ? (string) $payload["request_uri"] : "";
            if (!str_contains($requestUri, $requestUriContains)) {
                continue;
            }
        }

        $findings = $payload["findings"] ?? array();
        if (!is_array($findings)) {
            continue;
        }

        foreach ($findings as $finding) {
            if (!is_array($finding)) {
                continue;
            }

            if ((string) ($finding["sink_name"] ?? "") === $sink && (string) ($finding["sink_category"] ?? "") === $category) {
                $found = true;
                break 2;
            }
        }
    }

    if ($found) {
        echo "[ok] " . $assertion . " => " . $sink . "/" . $category . PHP_EOL;
        continue;
    }

    $executionMode = (string) ($assertionExecutionModes[$assertion] ?? "");
    if ($assertion === "rce_dl" && $executionMode === "cli_sidecar") {
        $sidecarFound = false;
        foreach ($lines as $line) {
            $payload = json_decode($line, true);
            if (!is_array($payload)) {
                continue;
            }

            if ($requestUriContains !== "") {
                $requestUri = is_scalar($payload["request_uri"] ?? null) ? (string) $payload["request_uri"] : "";
                if (!str_contains($requestUri, $requestUriContains)) {
                    continue;
                }
            }

            $findings = $payload["findings"] ?? array();
            if (!is_array($findings)) {
                continue;
            }

            foreach ($findings as $finding) {
                if (!is_array($finding)) {
                    continue;
                }

                if ((string) ($finding["sink_name"] ?? "") === "proc_open" && (string) ($finding["sink_category"] ?? "") === "rce") {
                    $sidecarFound = true;
                    break 2;
                }
            }
        }

        if ($sidecarFound) {
            echo "[ok] " . $assertion . " => proc_open/rce (cli_sidecar marker)" . PHP_EOL;
            continue;
        }
    }

    $missing[] = $assertion . ": expected finding " . $sink . "/" . $category . " not found in " . $path;
}

if ($missing !== array()) {
    fwrite(STDERR, "Remote vulnerable lab validation failed:" . PHP_EOL);
    foreach ($missing as $line) {
        fwrite(STDERR, "  - " . $line . PHP_EOL);
    }
    exit(1);
}

echo sprintf(
    "[ok] extension assertions summary: executed=%d skipped=%d strict=%s profile=%s",
    $optionalExecuted,
    $optionalSkipped,
    $strictExtensionProfile ? "true" : "false",
    $requestedProfile
) . PHP_EOL;

if ($summaryPath !== "") {
    $summaryDir = dirname($summaryPath);
    if (!is_dir($summaryDir)) {
        @mkdir($summaryDir, 0775, true);
    }
    $total = $optionalExecuted + $optionalSkipped;
    $payload = array(
        "generated_at" => gmdate("c"),
        "script" => "run_remote_vuln_lab_tests.sh",
        "profile" => $requestedProfile,
        "strict" => (bool) $strictExtensionProfile,
        "optional_assertions_total" => $total,
        "optional_assertions_executed" => $optionalExecuted,
        "optional_assertions_skipped" => $optionalSkipped,
        "skip_rate" => $total > 0 ? round((float) $optionalSkipped / (float) $total, 6) : 0.0,
        "capability_assertions" => $capabilityAssertions,
        "assertion_execution_modes" => $assertionExecutionModes,
        "required_assertions_for_profile" => $requiredByProfile,
    );
    $encoded = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    if (is_string($encoded)) {
        @file_put_contents($summaryPath, $encoded . PHP_EOL);
    }
}

' "${REMOTE_PROJECT_ROOT}" "${CAPABILITY_ASSERTIONS_JSON}" "${STRICT_EXTENSION_PROFILE}" "${EXTENSION_PROFILE}" "${REMOTE_PROJECT_ROOT}/.remote_vuln_lab_runtime/extension_assertions_summary.json"
REMOTE
then
  echo "[remote-test] Validation failed. Dumping remote findings and logs..." >&2
  ssh_exec "${REMOTE_CMD}" <<'REMOTE'
set -euo pipefail

RUNTIME_DIR="${REMOTE_PROJECT_ROOT}/.remote_vuln_lab_runtime"

echo "--- findings ---"
for file in "${RUNTIME_DIR}/findings"/*.jsonl; do
  echo "## ${file}"
  if [[ -f "${file}" ]]; then
    cat "${file}" || true
  fi
done

echo "--- logs ---"
for file in "${RUNTIME_DIR}/logs"/*.log; do
  echo "## ${file}"
  if [[ -f "${file}" ]]; then
    tail -n 100 "${file}" || true
  fi
done
REMOTE
  exit 1
fi

echo "[remote-test] PASS: remote vulnerable app taint tracing checks succeeded on ${HOST} (profile=${EXTENSION_PROFILE}, strict=${STRICT_EXTENSION_PROFILE})."
