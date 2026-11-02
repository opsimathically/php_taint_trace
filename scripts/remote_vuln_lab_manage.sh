#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME_DIR="${ROOT_DIR}/.remote_vuln_lab_runtime"
PID_DIR="${RUNTIME_DIR}/pids"
LOG_DIR="${RUNTIME_DIR}/logs"
FINDINGS_DIR="${RUNTIME_DIR}/findings"
CAPABILITIES_PATH="${RUNTIME_DIR}/capabilities.json"
PROFILE_PATH="${RUNTIME_DIR}/extension_profile"

EXT_PATH="${ROOT_DIR}/ext/xmark/modules/xmark.so"
PREPEND_PATH="${ROOT_DIR}/scripts/auto_prepend.php"
APP_ROOT="${ROOT_DIR}/tests/fixtures/vuln_lab_apps"
LAB_PHP_BIN="${PHP_TAINT_TRACE_LAB_PHP_BIN:-}"
LAB_PHP_CONFIG_BIN="${PHP_TAINT_TRACE_LAB_PHP_CONFIG_BIN:-}"

declare -A APP_PORTS=(
  ["xss_app"]=19081
  ["rce_app"]=19082
  ["file_app"]=19083
  ["ssrf_app"]=19084
  ["sqli_app"]=19085
  ["idor_app"]=19086
  ["xxe_app"]=19087
)

APP_ORDER=(
  "xss_app"
  "rce_app"
  "file_app"
  "ssrf_app"
  "sqli_app"
  "idor_app"
  "xxe_app"
)

if [[ -z "${LAB_PHP_BIN}" ]]; then
  if command -v php8.3 >/dev/null 2>&1; then
    LAB_PHP_BIN="php8.3"
  else
    LAB_PHP_BIN="php"
  fi
fi

if [[ -z "${LAB_PHP_CONFIG_BIN}" ]]; then
  if [[ "${LAB_PHP_BIN}" =~ ^php([0-9]+\.[0-9]+)$ ]] && command -v "php-config${BASH_REMATCH[1]}" >/dev/null 2>&1; then
    LAB_PHP_CONFIG_BIN="php-config${BASH_REMATCH[1]}"
  else
    LAB_PHP_CONFIG_BIN="php-config"
  fi
fi

usage() {
  cat <<'EOF'
Usage: scripts/remote_vuln_lab_manage.sh <start|stop|restart|status|reset|capabilities|profile>

Controls vulnerable PHP lab applications on the current host.

Actions:
  capabilities [--json]   Emit extension/function capability snapshot.
  profile <name>          Persist extension profile (base|extended_sql|extended_rce|extended_all).
EOF
}

require_base_files() {
  if [[ ! -f "${EXT_PATH}" ]]; then
    echo "Missing extension: ${EXT_PATH}" >&2
    echo "Build with: ./scripts/build_xmark_extension.sh" >&2
    exit 1
  fi

  if [[ ! -f "${PREPEND_PATH}" ]]; then
    echo "Missing auto prepend entrypoint: ${PREPEND_PATH}" >&2
    exit 1
  fi

  if [[ ! -d "${APP_ROOT}" ]]; then
    echo "Missing vulnerable app fixtures at: ${APP_ROOT}" >&2
    exit 1
  fi
}

ensure_runtime_dirs() {
  mkdir -p "${PID_DIR}" "${LOG_DIR}" "${FINDINGS_DIR}"
}

normalize_extension_profile() {
  local raw="${1:-base}"
  raw="$(printf '%s' "${raw}" | tr '[:upper:]' '[:lower:]' | xargs)"
  case "${raw}" in
    base|extended_sql|extended_rce|extended_all)
      printf '%s\n' "${raw}"
      ;;
    *)
      printf 'base\n'
      ;;
  esac
}

current_extension_profile() {
  local raw="${PHP_TAINT_TRACE_LAB_EXTENSION_PROFILE:-}"
  if [[ -z "${raw}" && -f "${PROFILE_PATH}" ]]; then
    raw="$(cat "${PROFILE_PATH}" 2>/dev/null || true)"
  fi

  normalize_extension_profile "${raw}"
}

profile_enables() {
  local profile="$1"
  local feature="$2"

  case "${feature}" in
    extended_sql)
      [[ "${profile}" == "extended_sql" || "${profile}" == "extended_all" ]]
      ;;
    extended_rce)
      [[ "${profile}" == "extended_rce" || "${profile}" == "extended_all" ]]
      ;;
    *)
      return 1
      ;;
  esac
}

env_flag_enabled() {
  local raw="${1:-}"
  raw="$(printf '%s' "${raw}" | tr '[:upper:]' '[:lower:]' | xargs)"
  case "${raw}" in
    1|true|yes|on)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

resolve_php_extension_dir() {
  local extension_dir=""
  if command -v "${LAB_PHP_CONFIG_BIN}" >/dev/null 2>&1; then
    extension_dir="$("${LAB_PHP_CONFIG_BIN}" --extension-dir 2>/dev/null || true)"
  fi

  if [[ -z "${extension_dir}" ]]; then
    extension_dir="$("${LAB_PHP_BIN}" -n -r 'echo ini_get("extension_dir");' 2>/dev/null || true)"
  fi

  printf '%s\n' "${extension_dir}"
}

append_extension_if_available() {
  local extension_dir="$1"
  local extension_name="$2"
  local -n output_ref="$3"

  if [[ -z "${extension_dir}" ]]; then
    return
  fi

  if [[ -f "${extension_dir}/${extension_name}" || -f "${extension_dir}/${extension_name}.so" ]]; then
    output_ref+=(-d "extension=${extension_name}")
  fi
}

append_zend_extension_if_available() {
  local extension_dir="$1"
  local extension_name="$2"
  local -n output_ref="$3"

  if [[ -z "${extension_dir}" ]]; then
    return
  fi

  if [[ -f "${extension_dir}/${extension_name}" || -f "${extension_dir}/${extension_name}.so" ]]; then
    output_ref+=(-d "zend_extension=${extension_name}")
  fi
}

build_extra_php_args() {
  local app="$1"
  local -n args_ref="$2"
  args_ref=()

  local profile
  profile="$(current_extension_profile)"

  local extension_dir
  extension_dir="$(resolve_php_extension_dir)"
  if [[ -n "${extension_dir}" ]]; then
    args_ref+=(-d "extension_dir=${extension_dir}")
  fi

  if [[ "${app}" == "sqli_app" ]]; then
    args_ref+=(-d "extension=mysqlnd")
    args_ref+=(-d "extension=pdo")
    args_ref+=(-d "extension=pdo_mysql")
    args_ref+=(-d "extension=mysqli")
    append_extension_if_available "${extension_dir}" "sqlite3" args_ref
    append_extension_if_available "${extension_dir}" "pdo_sqlite" args_ref

    if profile_enables "${profile}" "extended_sql"; then
      append_extension_if_available "${extension_dir}" "pgsql" args_ref
      append_extension_if_available "${extension_dir}" "pdo_pgsql" args_ref
      append_extension_if_available "${extension_dir}" "sqlsrv" args_ref
      append_extension_if_available "${extension_dir}" "pdo_sqlsrv" args_ref
      append_extension_if_available "${extension_dir}" "oci8" args_ref
    fi
  fi

  if [[ "${app}" == "ssrf_app" ]]; then
    append_extension_if_available "${extension_dir}" "curl" args_ref
    append_extension_if_available "${extension_dir}" "soap" args_ref
  fi

  if [[ "${app}" == "rce_app" ]] && profile_enables "${profile}" "extended_rce"; then
    append_extension_if_available "${extension_dir}" "expect" args_ref
  fi

  if [[ "${app}" == "xxe_app" ]]; then
    args_ref+=(-d "extension=xml")
    args_ref+=(-d "extension=dom")
    args_ref+=(-d "extension=simplexml")
    args_ref+=(-d "extension=xmlreader")
  fi

  if env_flag_enabled "${PHP_TAINT_TRACE_LAB_ENABLE_XDEBUG:-0}"; then
    append_zend_extension_if_available "${extension_dir}" "xdebug" args_ref
    args_ref+=(-d "xdebug.mode=${PHP_TAINT_TRACE_LAB_XDEBUG_MODE:-debug}")
    args_ref+=(-d "xdebug.start_with_request=${PHP_TAINT_TRACE_LAB_XDEBUG_START_WITH_REQUEST:-trigger}")
    args_ref+=(-d "xdebug.discover_client_host=0")
    args_ref+=(-d "xdebug.client_host=${PHP_TAINT_TRACE_LAB_XDEBUG_CLIENT_HOST:-127.0.0.1}")
    args_ref+=(-d "xdebug.client_port=${PHP_TAINT_TRACE_LAB_XDEBUG_CLIENT_PORT:-19003}")
    args_ref+=(-d "xdebug.idekey=${PHP_TAINT_TRACE_LAB_XDEBUG_IDEKEY:-php-taint-trace}")
    args_ref+=(-d "xdebug.log_level=${PHP_TAINT_TRACE_LAB_XDEBUG_LOG_LEVEL:-0}")
  fi
}

wait_for_port() {
  local port="$1"
  local ready=0
  for _ in $(seq 1 60); do
    if "${LAB_PHP_BIN}" -r '
$fp = @fsockopen("127.0.0.1", (int) $argv[1], $errno, $errstr, 0.1);
if ($fp !== false) {
    fclose($fp);
    exit(0);
}
exit(1);
' "${port}"; then
      ready=1
      break
    fi
    sleep 0.1
  done

  [[ ${ready} -eq 1 ]]
}

port_is_open() {
  local port="$1"
  "${LAB_PHP_BIN}" -r '
$fp = @fsockopen("127.0.0.1", (int) $argv[1], $errno, $errstr, 0.1);
if ($fp !== false) {
    fclose($fp);
    exit(0);
}
exit(1);
' "${port}" >/dev/null 2>&1
}

listener_pids_for_port() {
  local port="$1"

  if command -v lsof >/dev/null 2>&1; then
    lsof -tiTCP:"${port}" -sTCP:LISTEN 2>/dev/null | sed '/^[[:space:]]*$/d' | sort -u
    return 0
  fi

  if command -v fuser >/dev/null 2>&1; then
    fuser -n tcp "${port}" 2>/dev/null | tr ' ' '\n' | sed '/^[[:space:]]*$/d' | sort -u
    return 0
  fi
}

dump_port_debug() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -ltnp "sport = :${port}" 2>/dev/null || true
  fi
}

terminate_listener_on_port() {
  local port="$1"
  local pids
  pids="$(listener_pids_for_port "${port}" || true)"
  if [[ -z "${pids}" ]]; then
    return 0
  fi

  while IFS= read -r pid; do
    [[ -z "${pid}" ]] && continue
    if kill -0 "${pid}" >/dev/null 2>&1; then
      kill "${pid}" >/dev/null 2>&1 || true
    fi
  done <<< "${pids}"

  for _ in $(seq 1 40); do
    if ! port_is_open "${port}"; then
      return 0
    fi
    sleep 0.1
  done

  return 1
}

start_app() {
  local app="$1"
  local port="$2"
  local app_docroot="${APP_ROOT}/${app}/public"
  local pid_path="${PID_DIR}/${app}.pid"
  local log_path="${LOG_DIR}/${app}.log"
  local findings_path="${FINDINGS_DIR}/${app}.jsonl"

  if [[ ! -d "${app_docroot}" ]]; then
    echo "Missing app docroot for ${app}: ${app_docroot}" >&2
    exit 1
  fi

  if [[ -f "${pid_path}" ]]; then
    local existing_pid
    existing_pid="$(cat "${pid_path}")"
    if [[ -n "${existing_pid}" ]] && kill -0 "${existing_pid}" >/dev/null 2>&1; then
      echo "${app} already running on port ${port} (pid ${existing_pid})"
      return
    fi
    rm -f "${pid_path}"
  fi

  if port_is_open "${port}"; then
    echo "Detected existing listener on port ${port}; attempting cleanup before starting ${app}" >&2
    terminate_listener_on_port "${port}" || true
  fi

  if port_is_open "${port}"; then
    echo "Port ${port} remains in use; cannot start ${app}" >&2
    dump_port_debug "${port}" >&2 || true
    exit 1
  fi

  : > "${findings_path}"

  local extra_php_args=()
  build_extra_php_args "${app}" extra_php_args

  (
    export PHP_TAINT_TRACE_ENABLED=1
    export PHP_TAINT_TRACE_FINDINGS_FILE="${findings_path}"
    export PHP_TAINT_TRACE_ERROR_LOG=0
    export PHP_TAINT_TRACE_CLEAR_AFTER_FLUSH=1
    export PHP_TAINT_TRACE_ENABLE_VERIFIER="${PHP_TAINT_TRACE_ENABLE_VERIFIER:-0}"
    export PHP_TAINT_TRACE_VERIFIER_RUNTIME_DIR="${PHP_TAINT_TRACE_VERIFIER_RUNTIME_DIR:-${RUNTIME_DIR}/verifier}"
    export PHP_TAINT_TRACE_VERIFIER_REPLAY_TARGET="${PHP_TAINT_TRACE_VERIFIER_REPLAY_TARGET:-local}"
    export PHP_TAINT_TRACE_ENABLE_OPCODE_HOOKS="${PHP_TAINT_TRACE_ENABLE_OPCODE_HOOKS:-1}"
    export PHP_TAINT_TRACE_OPCODE_HOOK_PROFILE="${PHP_TAINT_TRACE_OPCODE_HOOK_PROFILE:-full}"
    export PHP_TAINT_TRACE_LAB_DB_HOST="${PHP_TAINT_TRACE_LAB_DB_HOST:-localhost}"
    export PHP_TAINT_TRACE_LAB_DB_PORT="${PHP_TAINT_TRACE_LAB_DB_PORT:-3306}"
    export PHP_TAINT_TRACE_LAB_DB_NAME="${PHP_TAINT_TRACE_LAB_DB_NAME:-php_taint_lab}"
    export PHP_TAINT_TRACE_LAB_DB_USER="${PHP_TAINT_TRACE_LAB_DB_USER:-php_taint}"
    export PHP_TAINT_TRACE_LAB_DB_PASSWORD="${PHP_TAINT_TRACE_LAB_DB_PASSWORD:-php_taint_password}"
    export PHP_TAINT_TRACE_LAB_DB_SOCKET="${PHP_TAINT_TRACE_LAB_DB_SOCKET:-/run/mysqld/mysqld.sock}"
    export PHP_TAINT_TRACE_LAB_EXT_PATH="${EXT_PATH}"
    export PHP_TAINT_TRACE_LAB_PREPEND_PATH="${PREPEND_PATH}"
    export PHP_TAINT_TRACE_LAB_DL_SIDECAR_ENABLED=1

    exec "${LAB_PHP_BIN}" -n \
      -d "extension=${EXT_PATH}" \
      -d "auto_prepend_file=${PREPEND_PATH}" \
      "${extra_php_args[@]}" \
      -S "0.0.0.0:${port}" \
      -t "${app_docroot}"
  ) >"${log_path}" 2>&1 &

  local pid="$!"
  echo "${pid}" > "${pid_path}"

  if ! wait_for_port "${port}"; then
    echo "Failed to start ${app} on port ${port}" >&2
    echo "--- ${app} log ---" >&2
    cat "${log_path}" >&2 || true
    exit 1
  fi

  if ! kill -0 "${pid}" >/dev/null 2>&1; then
    echo "Process for ${app} exited early after startup on port ${port}" >&2
    echo "--- ${app} log ---" >&2
    cat "${log_path}" >&2 || true
    dump_port_debug "${port}" >&2 || true
    exit 1
  fi

  local listener_pids
  listener_pids="$(listener_pids_for_port "${port}" || true)"
  if [[ -n "${listener_pids}" ]] && ! grep -qx "${pid}" <<< "${listener_pids}"; then
    echo "Port ${port} listener does not match expected pid ${pid} for ${app}" >&2
    echo "Observed listener pid(s): ${listener_pids}" >&2
    echo "--- ${app} log ---" >&2
    cat "${log_path}" >&2 || true
    dump_port_debug "${port}" >&2 || true
    exit 1
  fi

  echo "Started ${app} on port ${port} (pid ${pid})"
}

capabilities_json() {
  local rce_args=()
  local sqli_args=()
  local ssrf_args=()
  local xxe_args=()
  build_extra_php_args "rce_app" rce_args
  build_extra_php_args "sqli_app" sqli_args
  build_extra_php_args "ssrf_app" ssrf_args
  build_extra_php_args "xxe_app" xxe_args

  local profile
  profile="$(current_extension_profile)"
  local dl_cli_sidecar_available=0
  if [[ -f "${EXT_PATH}" && -f "${PREPEND_PATH}" ]]; then
    dl_cli_sidecar_available=1
  fi
  local probe_flags=(
    -d "display_errors=0"
    -d "display_startup_errors=0"
    -d "log_errors=1"
  )

  local rce_payload
  rce_payload="$("${LAB_PHP_BIN}" -n "${probe_flags[@]}" "${rce_args[@]}" -r '
$enableDlRaw = ini_get("enable_dl");
$enableDlNormalized = strtolower(trim((string) $enableDlRaw));
$enableDl = in_array($enableDlNormalized, array("1", "on", "true", "yes"), true);
$payload = array(
    "extensions" => array(
        "pcntl" => extension_loaded("pcntl"),
        "expect" => extension_loaded("expect"),
    ),
    "functions" => array(
        "exec" => function_exists("exec"),
        "shell_exec" => function_exists("shell_exec"),
        "popen" => function_exists("popen"),
        "passthru" => function_exists("passthru"),
        "proc_open" => function_exists("proc_open"),
        "unserialize" => function_exists("unserialize"),
        "pcntl_exec" => function_exists("pcntl_exec"),
        "expect_popen" => function_exists("expect_popen"),
        "dl" => function_exists("dl"),
    ),
    "ini" => array(
        "enable_dl_raw" => (string) $enableDlRaw,
        "enable_dl" => $enableDl,
    ),
    "loaded_extensions" => get_loaded_extensions(),
);
echo json_encode($payload);
')"

  local sqli_payload
  sqli_payload="$("${LAB_PHP_BIN}" -n "${probe_flags[@]}" "${sqli_args[@]}" -r '
$payload = array(
    "extensions" => array(
        "pgsql" => extension_loaded("pgsql"),
        "sqlsrv" => extension_loaded("sqlsrv"),
        "oci8" => extension_loaded("oci8"),
        "sqlite3" => extension_loaded("sqlite3"),
    ),
    "functions" => array(
        "mysqli_execute_query" => function_exists("mysqli_execute_query"),
        "pg_prepare" => function_exists("pg_prepare"),
        "pg_query_prepared" => function_exists("pg_query_prepared"),
        "pg_execute" => function_exists("pg_execute"),
        "pg_send_execute" => function_exists("pg_send_execute"),
        "sqlsrv_prepare" => function_exists("sqlsrv_prepare"),
        "sqlsrv_query" => function_exists("sqlsrv_query"),
        "oci_parse" => function_exists("oci_parse"),
        "oci_execute" => function_exists("oci_execute"),
        "pdo_query" => class_exists("PDO") && method_exists("PDO", "query"),
        "pdo_exec" => class_exists("PDO") && method_exists("PDO", "exec"),
        "sqlite3_querysingle" => class_exists("SQLite3") && method_exists("SQLite3", "querySingle"),
        "sqlite3_query" => class_exists("SQLite3") && method_exists("SQLite3", "query"),
        "sqlite3_exec" => class_exists("SQLite3") && method_exists("SQLite3", "exec"),
    ),
    "loaded_extensions" => get_loaded_extensions(),
);
echo json_encode($payload);
')"

  local file_payload
  file_payload="$("${LAB_PHP_BIN}" -n "${probe_flags[@]}" -r '
$payload = array(
    "functions" => array(
        "fopen" => function_exists("fopen"),
        "readfile" => function_exists("readfile"),
    ),
);
echo json_encode($payload);
')"

  local ssrf_payload
  ssrf_payload="$("${LAB_PHP_BIN}" -n "${probe_flags[@]}" "${ssrf_args[@]}" -r '
$payload = array(
    "extensions" => array(
        "curl" => extension_loaded("curl"),
        "soap" => extension_loaded("soap"),
    ),
    "functions" => array(
        "curl_exec" => function_exists("curl_exec"),
        "curl_setopt" => function_exists("curl_setopt"),
        "curl_setopt_array" => function_exists("curl_setopt_array"),
        "curl_multi_init" => function_exists("curl_multi_init"),
        "curl_multi_add_handle" => function_exists("curl_multi_add_handle"),
        "curl_multi_exec" => function_exists("curl_multi_exec"),
        "fsockopen" => function_exists("fsockopen"),
        "get_headers" => function_exists("get_headers"),
        "soapclient_construct" => class_exists("SoapClient"),
        "soapclient_location" => class_exists("SoapClient"),
        "soapclient_setlocation" => class_exists("SoapClient") && method_exists("SoapClient", "__setLocation"),
    ),
    "loaded_extensions" => get_loaded_extensions(),
);
echo json_encode($payload);
')"

  local xxe_payload
  xxe_payload="$("${LAB_PHP_BIN}" -n "${probe_flags[@]}" "${xxe_args[@]}" -r '
$payload = array(
    "extensions" => array(
        "dom" => extension_loaded("dom"),
        "xmlreader" => extension_loaded("xmlreader"),
        "simplexml" => extension_loaded("simplexml"),
    ),
    "functions" => array(
        "domdocument_load" => class_exists("DOMDocument") && method_exists("DOMDocument", "load"),
        "domdocument_loadxml" => class_exists("DOMDocument") && method_exists("DOMDocument", "loadXML"),
        "xmlreader_open" => class_exists("XMLReader") && method_exists("XMLReader", "open"),
        "xmlreader_xml" => class_exists("XMLReader") && method_exists("XMLReader", "XML"),
        "simplexml_load_string" => function_exists("simplexml_load_string"),
        "simplexml_load_file" => function_exists("simplexml_load_file"),
    ),
    "loaded_extensions" => get_loaded_extensions(),
);
echo json_encode($payload);
')"

  "${LAB_PHP_BIN}" -r '
$profile = (string) ($argv[1] ?? "base");
$rce = json_decode((string) ($argv[2] ?? "{}"), true);
$sqli = json_decode((string) ($argv[3] ?? "{}"), true);
$file = json_decode((string) ($argv[4] ?? "{}"), true);
$ssrf = json_decode((string) ($argv[5] ?? "{}"), true);
$xxe = json_decode((string) ($argv[6] ?? "{}"), true);
$dlCliSidecarAvailable = filter_var((string) ($argv[7] ?? "0"), FILTER_VALIDATE_BOOL);
$opcodeHooksRaw = getenv("PHP_TAINT_TRACE_ENABLE_OPCODE_HOOKS");
$opcodeHooksEnabled = true;
if ($opcodeHooksRaw !== false && trim((string) $opcodeHooksRaw) !== "") {
    $normalizedOpcodeHooksEnabled = filter_var((string) $opcodeHooksRaw, FILTER_VALIDATE_BOOL, FILTER_NULL_ON_FAILURE);
    if (is_bool($normalizedOpcodeHooksEnabled)) {
        $opcodeHooksEnabled = $normalizedOpcodeHooksEnabled;
    }
}
$opcodeHookProfile = strtolower(trim((string) getenv("PHP_TAINT_TRACE_OPCODE_HOOK_PROFILE")));
if ($opcodeHookProfile === "") {
    $opcodeHookProfile = "full";
}
if (in_array($opcodeHookProfile, array("disabled", "off", "none"), true)) {
    $opcodeHooksEnabled = false;
}
if (!is_array($rce)) {
    $rce = array();
}
if (!is_array($sqli)) {
    $sqli = array();
}
if (!is_array($file)) {
    $file = array();
}
if (!is_array($ssrf)) {
    $ssrf = array();
}
if (!is_array($xxe)) {
    $xxe = array();
}

$rceFunctions = is_array($rce["functions"] ?? null) ? $rce["functions"] : array();
$sqliFunctions = is_array($sqli["functions"] ?? null) ? $sqli["functions"] : array();
$fileFunctions = is_array($file["functions"] ?? null) ? $file["functions"] : array();
$ssrfFunctions = is_array($ssrf["functions"] ?? null) ? $ssrf["functions"] : array();
$xxeFunctions = is_array($xxe["functions"] ?? null) ? $xxe["functions"] : array();
$rceExtensions = is_array($rce["extensions"] ?? null) ? $rce["extensions"] : array();
$sqliExtensions = is_array($sqli["extensions"] ?? null) ? $sqli["extensions"] : array();
$ssrfExtensions = is_array($ssrf["extensions"] ?? null) ? $ssrf["extensions"] : array();
$xxeExtensions = is_array($xxe["extensions"] ?? null) ? $xxe["extensions"] : array();
$rceIni = is_array($rce["ini"] ?? null) ? $rce["ini"] : array();
$dlEnabled = (bool) ($rceIni["enable_dl"] ?? false);

$labTargetSapi = "cli-server";
$dlSupportedSapies = array("cli", "cgi", "embed");
$dlSupportedInLabRuntime = in_array($labTargetSapi, $dlSupportedSapies, true);
$dlExecutionMode = $dlSupportedInLabRuntime ? "same_sapi" : ($dlCliSidecarAvailable ? "cli_sidecar" : "unavailable");

$assertions = array(
    "rce_exec" => array(
        "available" => (bool) ($rceFunctions["exec"] ?? false),
        "capability_key" => "exec",
    ),
    "rce_shell_exec" => array(
        "available" => (bool) ($rceFunctions["shell_exec"] ?? false),
        "capability_key" => "shell_exec",
    ),
    "rce_popen" => array(
        "available" => (bool) ($rceFunctions["popen"] ?? false),
        "capability_key" => "popen",
    ),
    "rce_passthru" => array(
        "available" => (bool) ($rceFunctions["passthru"] ?? false),
        "capability_key" => "passthru",
    ),
    "rce_proc_open" => array(
        "available" => (bool) ($rceFunctions["proc_open"] ?? false),
        "capability_key" => "proc_open",
    ),
    "rce_unserialize_template" => array(
        "available" => (bool) ($rceFunctions["unserialize"] ?? false),
        "capability_key" => "unserialize",
    ),
    "rce_include_or_eval" => array(
        "available" => $opcodeHooksEnabled,
        "capability_key" => "include_or_eval",
    ),
    "rce_pcntl_exec" => array(
        "available" => (bool) ($rceFunctions["pcntl_exec"] ?? false),
        "capability_key" => "pcntl_exec",
    ),
    "rce_expect_popen" => array(
        "available" => (bool) ($rceFunctions["expect_popen"] ?? false),
        "capability_key" => "expect_popen",
    ),
    "rce_dl" => array(
        "available" => (bool) ($rceFunctions["dl"] ?? false) && $dlEnabled && ($dlSupportedInLabRuntime || $dlCliSidecarAvailable),
        "capability_key" => "dl",
        "execution_mode" => $dlExecutionMode,
    ),
    "file_fopen" => array(
        "available" => (bool) ($fileFunctions["fopen"] ?? false),
        "capability_key" => "fopen",
    ),
    "file_readfile" => array(
        "available" => (bool) ($fileFunctions["readfile"] ?? false),
        "capability_key" => "readfile",
    ),
    "ssrf_soapclient_construct" => array(
        "available" => (bool) ($ssrfFunctions["soapclient_construct"] ?? false),
        "capability_key" => "soapclient_construct",
    ),
    "ssrf_soapclient_location" => array(
        "available" => (bool) ($ssrfFunctions["soapclient_location"] ?? false),
        "capability_key" => "soapclient_location",
    ),
    "ssrf_soapclient_setlocation" => array(
        "available" => (bool) ($ssrfFunctions["soapclient_setlocation"] ?? false),
        "capability_key" => "soapclient_setlocation",
    ),
    "ssrf_curl_setopt" => array(
        "available" => (bool) ($ssrfFunctions["curl_exec"] ?? false) && (bool) ($ssrfFunctions["curl_setopt"] ?? false),
        "capability_key" => "curl_setopt",
    ),
    "ssrf_curl_setopt_array" => array(
        "available" => (bool) ($ssrfFunctions["curl_exec"] ?? false) && (bool) ($ssrfFunctions["curl_setopt_array"] ?? false),
        "capability_key" => "curl_setopt_array",
    ),
    "ssrf_curl_multi_setopt" => array(
        "available" => (bool) ($ssrfFunctions["curl_multi_init"] ?? false)
            && (bool) ($ssrfFunctions["curl_multi_add_handle"] ?? false)
            && (bool) ($ssrfFunctions["curl_multi_exec"] ?? false)
            && (bool) ($ssrfFunctions["curl_setopt"] ?? false),
        "capability_key" => "curl_multi_setopt",
    ),
    "ssrf_curl_multi_setopt_array" => array(
        "available" => (bool) ($ssrfFunctions["curl_multi_init"] ?? false)
            && (bool) ($ssrfFunctions["curl_multi_add_handle"] ?? false)
            && (bool) ($ssrfFunctions["curl_multi_exec"] ?? false)
            && (bool) ($ssrfFunctions["curl_setopt_array"] ?? false),
        "capability_key" => "curl_multi_setopt_array",
    ),
    "ssrf_fsockopen" => array(
        "available" => (bool) ($ssrfFunctions["fsockopen"] ?? false),
        "capability_key" => "fsockopen",
    ),
    "ssrf_get_headers" => array(
        "available" => (bool) ($ssrfFunctions["get_headers"] ?? false),
        "capability_key" => "get_headers",
    ),
    "sqli_pg_query_prepared" => array(
        "available" => (bool) ($sqliFunctions["pg_query_prepared"] ?? false),
        "capability_key" => "pg_query_prepared",
    ),
    "sqli_pg_prepare" => array(
        "available" => (bool) ($sqliFunctions["pg_prepare"] ?? false),
        "capability_key" => "pg_prepare",
    ),
    "sqli_pg_execute" => array(
        "available" => (bool) ($sqliFunctions["pg_execute"] ?? false),
        "capability_key" => "pg_execute",
    ),
    "sqli_pg_send_execute" => array(
        "available" => (bool) ($sqliFunctions["pg_send_execute"] ?? false),
        "capability_key" => "pg_send_execute",
    ),
    "sqli_sqlsrv_query" => array(
        "available" => (bool) ($sqliFunctions["sqlsrv_query"] ?? false),
        "capability_key" => "sqlsrv_query",
    ),
    "sqli_pdo_query" => array(
        "available" => (bool) ($sqliFunctions["pdo_query"] ?? false),
        "capability_key" => "pdo_query",
    ),
    "sqli_pdo_exec" => array(
        "available" => (bool) ($sqliFunctions["pdo_exec"] ?? false),
        "capability_key" => "pdo_exec",
    ),
    "sqli_sqlite3_querysingle" => array(
        "available" => (bool) ($sqliFunctions["sqlite3_querysingle"] ?? false),
        "capability_key" => "sqlite3_querysingle",
    ),
    "sqli_sqlite3_query" => array(
        "available" => (bool) ($sqliFunctions["sqlite3_query"] ?? false),
        "capability_key" => "sqlite3_query",
    ),
    "sqli_sqlite3_exec" => array(
        "available" => (bool) ($sqliFunctions["sqlite3_exec"] ?? false),
        "capability_key" => "sqlite3_exec",
    ),
    "sqli_mysqli_execute_query" => array(
        "available" => (bool) ($sqliFunctions["mysqli_execute_query"] ?? false),
        "capability_key" => "mysqli_execute_query",
    ),
    "sqli_sqlsrv_prepare" => array(
        "available" => (bool) ($sqliFunctions["sqlsrv_prepare"] ?? false),
        "capability_key" => "sqlsrv_prepare",
    ),
    "sqli_oci_parse" => array(
        "available" => (bool) ($sqliFunctions["oci_parse"] ?? false),
        "capability_key" => "oci_parse",
    ),
    "sqli_oci_execute" => array(
        "available" => (bool) ($sqliFunctions["oci_execute"] ?? false),
        "capability_key" => "oci_execute",
    ),
    "xxe_domdocument_load" => array(
        "available" => (bool) ($xxeFunctions["domdocument_load"] ?? false),
        "capability_key" => "domdocument_load",
    ),
    "xxe_domdocument_loadxml" => array(
        "available" => (bool) ($xxeFunctions["domdocument_loadxml"] ?? false),
        "capability_key" => "domdocument_loadxml",
    ),
    "xxe_xmlreader_open" => array(
        "available" => (bool) ($xxeFunctions["xmlreader_open"] ?? false),
        "capability_key" => "xmlreader_open",
    ),
    "xxe_xmlreader_xml" => array(
        "available" => (bool) ($xxeFunctions["xmlreader_xml"] ?? false),
        "capability_key" => "xmlreader_xml",
    ),
    "xxe_simplexml_load_string" => array(
        "available" => (bool) ($xxeFunctions["simplexml_load_string"] ?? false),
        "capability_key" => "simplexml_load_string",
    ),
    "xxe_simplexml_load_file" => array(
        "available" => (bool) ($xxeFunctions["simplexml_load_file"] ?? false),
        "capability_key" => "simplexml_load_file",
    ),
);

foreach ($assertions as $assertion => $row) {
    $reason = $row["available"]
        ? "capability_available"
        : "capability_unavailable_in_current_profile";
    if ($assertion === "rce_dl" && !$row["available"] && (bool) ($rceFunctions["dl"] ?? false) && $dlEnabled && !$dlSupportedInLabRuntime && !$dlCliSidecarAvailable) {
        $reason = "capability_unavailable_in_lab_sapi";
    }
    $assertions[$assertion]["reason"] = $reason;
    if ($assertion === "sqli_pg_query_prepared") {
        $assertions[$assertion]["reason"] = "legacy_function_not_supported_in_modern_pgsql";
    }
}

$profileGroups = array(
    "extended_sql" => array(
        "sqli_pg_prepare",
        "sqli_pg_execute",
        "sqli_pg_send_execute",
        "sqli_mysqli_execute_query",
        "sqli_pdo_query",
        "sqli_pdo_exec",
        "sqli_sqlite3_querysingle",
        "sqli_sqlite3_query",
        "sqli_sqlite3_exec",
        "sqli_sqlsrv_query",
        "sqli_sqlsrv_prepare",
        "sqli_oci_parse",
    ),
    "extended_rce" => array(
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
    ),
);

$profileTargets = array();
if ($profile === "extended_sql" || $profile === "extended_all") {
    $profileTargets = array_merge($profileTargets, $profileGroups["extended_sql"]);
}
if ($profile === "extended_rce" || $profile === "extended_all") {
    $profileTargets = array_merge($profileTargets, $profileGroups["extended_rce"]);
}
$profileTargets = array_values(array_unique($profileTargets));

$requiredForProfile = array();
$unavailableForProfile = array();
foreach ($profileTargets as $assertionName) {
    $available = (bool) ($assertions[$assertionName]["available"] ?? false);
    if ($available) {
        $requiredForProfile[] = $assertionName;
        continue;
    }
    $unavailableForProfile[] = $assertionName;
}

$payload = array(
    "generated_at" => gmdate("c"),
    "extension_profile" => $profile,
    "rce_runtime" => array(
        "extensions" => $rceExtensions,
        "functions" => $rceFunctions,
        "ini" => $rceIni,
        "opcode_hooks_enabled" => $opcodeHooksEnabled,
        "opcode_hook_profile" => $opcodeHookProfile,
        "loaded_extensions" => is_array($rce["loaded_extensions"] ?? null) ? array_values($rce["loaded_extensions"]) : array(),
    ),
    "sqli_runtime" => array(
        "extensions" => $sqliExtensions,
        "functions" => $sqliFunctions,
        "loaded_extensions" => is_array($sqli["loaded_extensions"] ?? null) ? array_values($sqli["loaded_extensions"]) : array(),
    ),
    "file_runtime" => array(
        "functions" => $fileFunctions,
    ),
    "ssrf_runtime" => array(
        "extensions" => $ssrfExtensions,
        "functions" => $ssrfFunctions,
        "loaded_extensions" => is_array($ssrf["loaded_extensions"] ?? null) ? array_values($ssrf["loaded_extensions"]) : array(),
    ),
    "xxe_runtime" => array(
        "extensions" => $xxeExtensions,
        "functions" => $xxeFunctions,
        "loaded_extensions" => is_array($xxe["loaded_extensions"] ?? null) ? array_values($xxe["loaded_extensions"]) : array(),
    ),
    "assertions" => $assertions,
    "required_assertions_for_profile" => $requiredForProfile,
    "unavailable_assertions_for_profile" => $unavailableForProfile,
    "strict_assertion_policy" => "host_capability_required",
    "lab_target_sapi" => $labTargetSapi,
    "dl_cli_sidecar_available" => (bool) $dlCliSidecarAvailable,
);

echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT) . PHP_EOL;
' "${profile}" "${rce_payload}" "${sqli_payload}" "${file_payload}" "${ssrf_payload}" "${xxe_payload}" "${dl_cli_sidecar_available}"
}

emit_capabilities() {
  local format="${1:-human}"
  local payload
  payload="$(capabilities_json)"
  printf '%s\n' "${payload}" > "${CAPABILITIES_PATH}"

  if [[ "${format}" == "json" ]]; then
    cat "${CAPABILITIES_PATH}"
    return
  fi

  "${LAB_PHP_BIN}" -r '
$payload = json_decode((string) ($argv[1] ?? "{}"), true);
if (!is_array($payload)) {
    fwrite(STDERR, "invalid capability payload" . PHP_EOL);
    exit(1);
}
echo "extension_profile: " . (string) ($payload["extension_profile"] ?? "base") . PHP_EOL;
$assertions = is_array($payload["assertions"] ?? null) ? $payload["assertions"] : array();
foreach ($assertions as $name => $row) {
    $available = (bool) ($row["available"] ?? false);
    $reason = (string) ($row["reason"] ?? "");
    echo sprintf(
        "%s: %s%s",
        (string) $name,
        $available ? "available" : "unavailable",
        $reason !== "" ? " (" . $reason . ")" : ""
    ) . PHP_EOL;
}
echo "capabilities_file: " . (string) ($argv[2] ?? "") . PHP_EOL;
' "${payload}" "${CAPABILITIES_PATH}"
}

persist_extension_profile() {
  local requested="${1:-base}"
  local profile
  profile="$(normalize_extension_profile "${requested}")"
  printf '%s\n' "${profile}" > "${PROFILE_PATH}"
  echo "Persisted extension profile: ${profile}"
}

stop_app() {
  local app="$1"
  local port="${2:-}"
  local pid_path="${PID_DIR}/${app}.pid"

  if [[ ! -f "${pid_path}" ]]; then
    if [[ -n "${port}" ]] && port_is_open "${port}"; then
      echo "${app} missing pid file but listener found on port ${port}; attempting cleanup"
      terminate_listener_on_port "${port}" || true
      if port_is_open "${port}"; then
        echo "Failed to clear listener for ${app} on port ${port}" >&2
        dump_port_debug "${port}" >&2 || true
      fi
    else
      echo "${app} not running"
    fi
    return
  fi

  local pid
  pid="$(cat "${pid_path}")"
  if [[ -n "${pid}" ]] && kill -0 "${pid}" >/dev/null 2>&1; then
    kill "${pid}" >/dev/null 2>&1 || true
    wait "${pid}" >/dev/null 2>&1 || true
    echo "Stopped ${app} (pid ${pid})"
  else
    echo "${app} pid file existed but process was not running"
  fi
  rm -f "${pid_path}"

  if [[ -n "${port}" ]] && port_is_open "${port}"; then
    echo "${app} listener still active on port ${port}; forcing cleanup"
    terminate_listener_on_port "${port}" || true
    if port_is_open "${port}"; then
      echo "Failed to clear listener for ${app} on port ${port}" >&2
      dump_port_debug "${port}" >&2 || true
    fi
  fi
}

reset_findings() {
  ensure_runtime_dirs
  for app in "${!APP_PORTS[@]}"; do
    : > "${FINDINGS_DIR}/${app}.jsonl"
  done
  echo "Reset findings files in ${FINDINGS_DIR}"
}

status_app() {
  local app="$1"
  local port="$2"
  local pid_path="${PID_DIR}/${app}.pid"
  local findings_path="${FINDINGS_DIR}/${app}.jsonl"

  if [[ -f "${pid_path}" ]]; then
    local pid
    pid="$(cat "${pid_path}")"
    if [[ -n "${pid}" ]] && kill -0 "${pid}" >/dev/null 2>&1; then
      echo "${app}: running (port=${port}, pid=${pid}, findings=${findings_path})"
      return
    fi
  fi

  echo "${app}: stopped (port=${port}, findings=${findings_path})"
}

main() {
  local action="${1:-}"
  if [[ -z "${action}" ]]; then
    usage >&2
    exit 1
  fi

  require_base_files
  ensure_runtime_dirs

  case "${action}" in
    start)
      for app in "${APP_ORDER[@]}"; do
        start_app "${app}" "${APP_PORTS[$app]}"
      done
      ;;
    stop)
      for app in "${APP_ORDER[@]}"; do
        stop_app "${app}" "${APP_PORTS[$app]}"
      done
      ;;
    restart)
      for app in "${APP_ORDER[@]}"; do
        stop_app "${app}" "${APP_PORTS[$app]}"
      done
      for app in "${APP_ORDER[@]}"; do
        start_app "${app}" "${APP_PORTS[$app]}"
      done
      ;;
    reset)
      reset_findings
      ;;
    status)
      echo "extension_profile: $(current_extension_profile)"
      for app in "${APP_ORDER[@]}"; do
        status_app "${app}" "${APP_PORTS[$app]}"
      done
      ;;
    capabilities)
      shift || true
      if [[ "${1:-}" == "--json" ]]; then
        emit_capabilities "json"
      else
        emit_capabilities "human"
      fi
      ;;
    profile)
      shift || true
      if [[ -z "${1:-}" ]]; then
        echo "profile action requires a value: base|extended_sql|extended_rce|extended_all" >&2
        exit 1
      fi
      persist_extension_profile "${1}"
      ;;
    *)
      echo "Unknown action: ${action}" >&2
      usage >&2
      exit 1
      ;;
  esac
}

main "$@"
