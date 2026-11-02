#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_PATH="${PHP_TAINT_TRACE_TEST_CONFIG:-${XDG_CONFIG_HOME:-${HOME}/.config}/php_taint_trace/testing_container_config.json}"
HOST_LABEL="${PHP_TAINT_TRACE_TEST_HOST_LABEL:-lab.example.invalid}"
REMOTE_ROOT="/opt/php_taint_trace_vuln_lab"
EXTENSION_PROFILE="${PHP_TAINT_TRACE_REMOTE_EXTENSION_PROFILE:-base}"
LAB_PHP_SERIES="${PHP_TAINT_TRACE_LAB_PHP_SERIES:-8.3}"
ORACLE_INSTANTCLIENT_BASIC_URL="${PHP_TAINT_TRACE_ORACLE_INSTANTCLIENT_BASIC_URL:-https://download.oracle.com/otn_software/linux/instantclient/2360000/instantclient-basiclite-linux.x64-23.6.0.24.10.zip}"
ORACLE_INSTANTCLIENT_SDK_URL="${PHP_TAINT_TRACE_ORACLE_INSTANTCLIENT_SDK_URL:-https://download.oracle.com/otn_software/linux/instantclient/2360000/instantclient-sdk-linux.x64-23.6.0.24.10.zip}"
ORACLE_INSTANTCLIENT_DIR="${PHP_TAINT_TRACE_ORACLE_INSTANTCLIENT_DIR:-}"

usage() {
  cat <<'EOF'
Usage: scripts/deploy_remote_vuln_lab.sh [--config PATH] [--host-label LABEL] [--remote-root PATH] [--profile base|extended_sql|extended_rce|extended_all] [--lab-php-series X.Y]

Deploys this repository to the configured remote host, builds the xmark extension,
and starts the vulnerable PHP lab apps with taint tracing enabled.

Optional environment for OCI8 provisioning:
  (Defaults are Oracle-hosted Instant Client 23.6 basiclite + sdk archives.)
  PHP_TAINT_TRACE_ORACLE_INSTANTCLIENT_BASIC_URL
  PHP_TAINT_TRACE_ORACLE_INSTANTCLIENT_SDK_URL
  PHP_TAINT_TRACE_ORACLE_INSTANTCLIENT_DIR
EOF
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
    --profile)
      EXTENSION_PROFILE="$2"
      shift 2
      ;;
    --lab-php-series)
      LAB_PHP_SERIES="$2"
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
    echo "Invalid --profile: ${EXTENSION_PROFILE}. Expected base|extended_sql|extended_rce|extended_all." >&2
    exit 1
    ;;
esac

if ! [[ "${LAB_PHP_SERIES}" =~ ^[0-9]+\.[0-9]+$ ]]; then
  echo "Invalid --lab-php-series: ${LAB_PHP_SERIES}. Expected major.minor (for example 8.3)." >&2
  exit 1
fi

for cmd in python3 ssh setsid rsync; do
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
required = ("ipv4", "ssh_username", "ssh_password", "sudopassword")
missing = [k for k in required if k not in entry or not str(entry[k]).strip()]
if missing:
    raise SystemExit(f"Missing required config keys for {label}: {', '.join(missing)}")
print(entry["ipv4"])
print(entry["ssh_username"])
print(entry["ssh_password"])
print(entry["sudopassword"])
PY
)

HOST="${_cfg[0]}"
SSH_USER="${_cfg[1]}"
SSH_PASSWORD="${_cfg[2]}"
SUDO_PASSWORD="${_cfg[3]}"

ASKPASS_SCRIPT="$(mktemp /tmp/php_taint_trace_askpass.XXXXXX)"
cleanup() {
  rm -f "${ASKPASS_SCRIPT}"
}
trap cleanup EXIT

cat > "${ASKPASS_SCRIPT}" <<'EOF'
#!/usr/bin/env sh
printf '%s\n' "$SSH_PASSWORD"
EOF
chmod 700 "${ASKPASS_SCRIPT}"

SSH_OPTS=(
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o PubkeyAuthentication=no
  -o PreferredAuthentications=password
  -o NumberOfPasswordPrompts=1
  -o ConnectTimeout=15
)
RSYNC_SSH_CMD="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PubkeyAuthentication=no -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1 -o ConnectTimeout=15"

ssh_exec() {
  DISPLAY=:0 \
  SSH_ASKPASS="${ASKPASS_SCRIPT}" \
  SSH_ASKPASS_REQUIRE=force \
  SSH_PASSWORD="${SSH_PASSWORD}" \
  setsid -w ssh "${SSH_OPTS[@]}" "${SSH_USER}@${HOST}" "$@"
}

echo "[deploy] Ensuring remote prerequisites"
REMOTE_PREPARE_CMD="$(printf \
  "SUDOPASS=%q REMOTE_USER=%q REMOTE_ROOT=%q EXTENSION_PROFILE=%q LAB_PHP_SERIES=%q ORACLE_INSTANTCLIENT_BASIC_URL=%q ORACLE_INSTANTCLIENT_SDK_URL=%q ORACLE_INSTANTCLIENT_DIR=%q bash -s" \
  "$SUDO_PASSWORD" \
  "$SSH_USER" \
  "$REMOTE_ROOT" \
  "$EXTENSION_PROFILE" \
  "$LAB_PHP_SERIES" \
  "$ORACLE_INSTANTCLIENT_BASIC_URL" \
  "$ORACLE_INSTANTCLIENT_SDK_URL" \
  "$ORACLE_INSTANTCLIENT_DIR" \
)"
ssh_exec "${REMOTE_PREPARE_CMD}" <<'REMOTE'
set -euo pipefail

run_sudo() {
  printf '%s\n' "$SUDOPASS" | sudo -S -k -p '' "$@"
}

LAB_PHP_BIN="php${LAB_PHP_SERIES}"
if ! command -v "${LAB_PHP_BIN}" >/dev/null 2>&1; then
  LAB_PHP_BIN="php"
fi

LAB_PHP_CONFIG_BIN="php-config${LAB_PHP_SERIES}"
if ! command -v "${LAB_PHP_CONFIG_BIN}" >/dev/null 2>&1; then
  LAB_PHP_CONFIG_BIN="php-config"
fi

apt_install_if_available() {
  local package_name="$1"
  local candidate=""
  candidate="$(apt-cache policy "${package_name}" 2>/dev/null | awk '/Candidate:/ { print $2; exit }')"
  if [[ -z "${candidate}" || "${candidate}" == "(none)" ]]; then
    return 1
  fi
  run_sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y "${package_name}"
  return 0
}

php_extension_dir() {
  local extension_dir=""
  if command -v "${LAB_PHP_CONFIG_BIN}" >/dev/null 2>&1; then
    extension_dir="$("${LAB_PHP_CONFIG_BIN}" --extension-dir 2>/dev/null || true)"
  fi
  if [[ -z "${extension_dir}" ]]; then
    extension_dir="$("${LAB_PHP_BIN}" -n -r 'echo ini_get("extension_dir");' 2>/dev/null || true)"
  fi
  printf '%s\n' "${extension_dir}"
}

run_pecl() {
  local pecl_path
  pecl_path="$(command -v pecl || true)"
  if [[ -z "${pecl_path}" ]]; then
    return 127
  fi

  run_sudo env PHP_PEAR_PHP_BIN="$(command -v "${LAB_PHP_BIN}")" "${pecl_path}" "$@"
}

have_extension_file() {
  local extension_name="$1"
  local extension_dir
  extension_dir="$(php_extension_dir)"
  if [[ -z "${extension_dir}" ]]; then
    return 1
  fi
  [[ -f "${extension_dir}/${extension_name}" || -f "${extension_dir}/${extension_name}.so" ]]
}

ensure_libaio_compat() {
  apt_install_if_available libaio1 || apt_install_if_available libaio1t64 || true

  local libaio_dir="/usr/lib/x86_64-linux-gnu"
  local legacy_link="${libaio_dir}/libaio.so.1"
  local t64_target="${libaio_dir}/libaio.so.1t64"
  if [[ ! -e "${legacy_link}" && -e "${t64_target}" ]]; then
    run_sudo ln -sf "${t64_target}" "${legacy_link}"
  fi

  run_sudo ldconfig || true
}

ensure_pecl_ready() {
  apt_install_if_available php-pear || true
  if ! command -v pecl >/dev/null 2>&1; then
    echo "[deploy] pecl is unavailable; cannot build optional extension" >&2
    return 1
  fi
  run_pecl channel-update pecl.php.net >/dev/null 2>&1 || true
  return 0
}

pecl_install_extension() {
  local extension_name="$1"
  local pecl_input="${2:-}"
  if have_extension_file "${extension_name}"; then
    return 0
  fi
  if ! ensure_pecl_ready; then
    return 1
  fi

  if [[ -n "${pecl_input}" ]]; then
    if ! printf '%s\n' "${pecl_input}" | run_pecl install -f "${extension_name}"; then
      echo "[deploy] pecl install failed for ${extension_name}" >&2
      return 1
    fi
  else
    if ! printf '\n' | run_pecl install -f "${extension_name}"; then
      echo "[deploy] pecl install failed for ${extension_name}" >&2
      return 1
    fi
  fi

  if ! have_extension_file "${extension_name}"; then
    echo "[deploy] extension file still missing after pecl install: ${extension_name}" >&2
    return 1
  fi

  return 0
}

ensure_microsoft_repo() {
  if [[ -f /etc/apt/sources.list.d/microsoft-prod.list ]]; then
    return 0
  fi

  local ubuntu_version
  ubuntu_version="$(. /etc/os-release && printf '%s' "${VERSION_ID:-}")"
  if [[ -z "${ubuntu_version}" ]]; then
    echo "[deploy] Unable to detect Ubuntu VERSION_ID; skipping Microsoft repo bootstrap." >&2
    return 1
  fi

  local deb_path="/tmp/packages-microsoft-prod.deb"
  if ! curl -fsSL "https://packages.microsoft.com/config/ubuntu/${ubuntu_version}/packages-microsoft-prod.deb" -o "${deb_path}"; then
    echo "[deploy] Unable to fetch Microsoft repo package for Ubuntu ${ubuntu_version}" >&2
    return 1
  fi

  run_sudo dpkg -i "${deb_path}" >/dev/null 2>&1 || run_sudo dpkg -i "${deb_path}"
  run_sudo apt-get update
  return 0
}

ensure_sqlsrv_extensions() {
  apt_install_if_available "php${LAB_PHP_SERIES}-odbc" || apt_install_if_available php-odbc || true
  apt_install_if_available unixodbc || true
  apt_install_if_available unixodbc-dev || true

  if apt_install_if_available "php${LAB_PHP_SERIES}-sqlsrv" || apt_install_if_available php-sqlsrv; then
    apt_install_if_available "php${LAB_PHP_SERIES}-pdo-sqlsrv" || apt_install_if_available php-pdo-sqlsrv || true
  fi

  if have_extension_file sqlsrv; then
    echo "[deploy] SQL Server sqlsrv extension available via distro packages."
    return 0
  fi

  if ! ensure_microsoft_repo; then
    echo "[deploy] SQL Server driver provisioning skipped: Microsoft repo unavailable." >&2
    return 1
  fi

  run_sudo env ACCEPT_EULA=Y DEBIAN_FRONTEND=noninteractive apt-get install -y msodbcsql18 || true
  run_sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y unixodbc-dev || true

  local failed=0
  pecl_install_extension sqlsrv || failed=1
  if [[ "${failed}" -ne 0 ]]; then
    echo "[deploy] SQL Server extension provisioning incomplete." >&2
    return 1
  fi

  echo "[deploy] SQL Server extensions provisioned via PECL."
  return 0
}

build_oci8_extension_manual() {
  local instantclient_dir="$1"

  local phpize_bin="phpize${LAB_PHP_SERIES}"
  if ! command -v "${phpize_bin}" >/dev/null 2>&1; then
    phpize_bin="phpize"
  fi
  local phpize_path
  phpize_path="$(command -v "${phpize_bin}" || true)"
  local php_config_path
  php_config_path="$(command -v "${LAB_PHP_CONFIG_BIN}" || true)"
  if [[ -z "${phpize_path}" || -z "${php_config_path}" ]]; then
    return 1
  fi

  local workdir="/tmp/php_taint_trace_oci8_build"
  local archive="${workdir}/oci8.tgz"
  run_sudo rm -rf "${workdir}"
  run_sudo mkdir -p "${workdir}"
  run_sudo curl -fsSL "https://pecl.php.net/get/oci8-3.4.1.tgz" -o "${archive}"
  run_sudo tar -xzf "${archive}" -C "${workdir}"

  local src_dir
  src_dir="$(run_sudo find "${workdir}" -maxdepth 1 -type d -name 'oci8-*' | head -n 1)"
  if [[ -z "${src_dir}" ]]; then
    run_sudo rm -rf "${workdir}"
    return 1
  fi

  if ! run_sudo bash -lc "set -euo pipefail; cd '${src_dir}'; '${phpize_path}' --clean >/dev/null 2>&1 || true; '${phpize_path}'; ./configure --with-php-config='${php_config_path}' --with-oci8=instantclient,'${instantclient_dir}'; make -j\$(nproc); make install"; then
    run_sudo rm -rf "${workdir}"
    return 1
  fi

  run_sudo rm -rf "${workdir}"
  return 0
}

ensure_expect_extension() {
  if [[ "${LAB_PHP_SERIES}" =~ ^8\. ]]; then
    echo "[deploy] expect extension skipped: upstream expect PECL package is not compatible with PHP ${LAB_PHP_SERIES}."
    return 0
  fi

  if apt_install_if_available "php${LAB_PHP_SERIES}-expect" || apt_install_if_available php-expect; then
    echo "[deploy] expect extension available via distro package."
    return 0
  fi

  apt_install_if_available expect || true
  apt_install_if_available tcl-dev || true
  apt_install_if_available tcl-expect-dev || true
  apt_install_if_available libexpect-dev || true
  apt_install_if_available build-essential || true
  apt_install_if_available pkg-config || true

  if pecl_install_extension expect; then
    echo "[deploy] expect extension provisioned via PECL."
    return 0
  fi

  echo "[deploy] expect extension provisioning incomplete." >&2
  return 1
}

install_oracle_instantclient_from_urls() {
  local basic_url="$1"
  local sdk_url="$2"
  local target_dir="$3"

  if [[ -z "${basic_url}" || -z "${sdk_url}" ]]; then
    return 1
  fi

  run_sudo mkdir -p "${target_dir}"
  if run_sudo find "${target_dir}" -maxdepth 1 -type d -name 'instantclient*' | grep -q .; then
    return 0
  fi

  local basic_archive="${target_dir}/$(basename "${basic_url}")"
  local sdk_archive="${target_dir}/$(basename "${sdk_url}")"

  run_sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y unzip libnsl2 || true
  ensure_libaio_compat
  run_sudo curl -fsSL "${basic_url}" -o "${basic_archive}"
  run_sudo curl -fsSL "${sdk_url}" -o "${sdk_archive}"

  case "${basic_archive}" in
    *.zip) run_sudo unzip -oq "${basic_archive}" -d "${target_dir}" ;;
    *.tar.gz|*.tgz) run_sudo tar -xzf "${basic_archive}" -C "${target_dir}" ;;
  esac
  case "${sdk_archive}" in
    *.zip) run_sudo unzip -oq "${sdk_archive}" -d "${target_dir}" ;;
    *.tar.gz|*.tgz) run_sudo tar -xzf "${sdk_archive}" -C "${target_dir}" ;;
  esac

  return 0
}

ensure_oci8_extension() {
  ensure_libaio_compat

  if apt_install_if_available "php${LAB_PHP_SERIES}-oci8" || apt_install_if_available php-oci8; then
    echo "[deploy] oci8 extension available via distro package."
    return 0
  fi

  if have_extension_file oci8; then
    return 0
  fi

  local instantclient_root="/opt/oracle"
  local configured_dir="${ORACLE_INSTANTCLIENT_DIR:-}"
  if [[ -n "${configured_dir}" ]]; then
    instantclient_root="$(dirname "${configured_dir}")"
  fi

  if [[ -z "${configured_dir}" ]]; then
    if ! install_oracle_instantclient_from_urls "${ORACLE_INSTANTCLIENT_BASIC_URL:-}" "${ORACLE_INSTANTCLIENT_SDK_URL:-}" "${instantclient_root}"; then
      echo "[deploy] oci8 provisioning skipped: Oracle Instant Client not present and no download URLs provided." >&2
      return 1
    fi
    configured_dir="$(run_sudo find "${instantclient_root}" -maxdepth 1 -type d -name 'instantclient*' | sort | tail -n 1)"
  fi

  if [[ -z "${configured_dir}" ]]; then
    echo "[deploy] oci8 provisioning failed: Instant Client directory not found." >&2
    return 1
  fi

  run_sudo sh -c "printf '%s\n' '${configured_dir}' > /etc/ld.so.conf.d/oracle-instantclient.conf"
  run_sudo ldconfig

  apt_install_if_available libnsl2 || true
  apt_install_if_available build-essential || true
  apt_install_if_available pkg-config || true

  if build_oci8_extension_manual "${configured_dir}" || pecl_install_extension oci8 "instantclient,${configured_dir}"; then
    echo "[deploy] oci8 extension provisioned via PECL."
    return 0
  fi

  echo "[deploy] oci8 extension provisioning incomplete." >&2
  return 1
}

run_sudo apt-get update
run_sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y \
  rsync composer \
  build-essential pkg-config curl ca-certificates gnupg unzip \
  mariadb-server

for required_php_package in "php${LAB_PHP_SERIES}" "php${LAB_PHP_SERIES}-cli" "php${LAB_PHP_SERIES}-dev"; do
  if ! apt_install_if_available "${required_php_package}"; then
    echo "[deploy] required PHP package unavailable: ${required_php_package}" >&2
    exit 1
  fi
done

for optional_php_package in \
  php-pear \
  "php${LAB_PHP_SERIES}-xml" \
  "php${LAB_PHP_SERIES}-soap" \
  "php${LAB_PHP_SERIES}-mbstring" \
  "php${LAB_PHP_SERIES}-curl" \
  "php${LAB_PHP_SERIES}-zip" \
  "php${LAB_PHP_SERIES}-readline" \
  "php${LAB_PHP_SERIES}-mysql" \
  "php${LAB_PHP_SERIES}-sqlite3" \
  "php${LAB_PHP_SERIES}-pgsql" \
  "php${LAB_PHP_SERIES}-opcache"
do
  apt_install_if_available "${optional_php_package}" || true
done

if [[ "${EXTENSION_PROFILE}" == "extended_sql" || "${EXTENSION_PROFILE}" == "extended_all" ]]; then
  apt_install_if_available "php${LAB_PHP_SERIES}-pgsql" || true
  ensure_sqlsrv_extensions || true
  ensure_oci8_extension || true
fi

if [[ "${EXTENSION_PROFILE}" == "extended_rce" || "${EXTENSION_PROFILE}" == "extended_all" ]]; then
  ensure_expect_extension || true
fi

run_sudo mkdir -p "${REMOTE_ROOT}"
run_sudo chown -R "${REMOTE_USER}:${REMOTE_USER}" "${REMOTE_ROOT}"

if command -v systemctl >/dev/null 2>&1; then
  run_sudo systemctl enable --now mariadb || run_sudo systemctl enable --now mysql || true
fi
run_sudo service mariadb start >/dev/null 2>&1 || run_sudo service mysql start >/dev/null 2>&1 || true

run_sudo mysql -e "CREATE DATABASE IF NOT EXISTS php_taint_lab CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
run_sudo mysql -e "CREATE USER IF NOT EXISTS 'php_taint'@'127.0.0.1' IDENTIFIED BY 'php_taint_password';"
run_sudo mysql -e "CREATE USER IF NOT EXISTS 'php_taint'@'localhost' IDENTIFIED BY 'php_taint_password';"
run_sudo mysql -e "CREATE USER IF NOT EXISTS 'php_taint'@'%' IDENTIFIED BY 'php_taint_password';"
run_sudo mysql -e "GRANT ALL PRIVILEGES ON php_taint_lab.* TO 'php_taint'@'127.0.0.1';"
run_sudo mysql -e "GRANT ALL PRIVILEGES ON php_taint_lab.* TO 'php_taint'@'localhost';"
run_sudo mysql -e "GRANT ALL PRIVILEGES ON php_taint_lab.* TO 'php_taint'@'%';"
run_sudo mysql -e "FLUSH PRIVILEGES;"

run_sudo mysql php_taint_lab -e "CREATE TABLE IF NOT EXISTS users (id INT PRIMARY KEY, username VARCHAR(128) NOT NULL);"
run_sudo mysql php_taint_lab -e "DELETE FROM users;"
run_sudo mysql php_taint_lab -e "INSERT INTO users (id, username) VALUES (1, 'alice'), (2, 'bob'), (3, 'charlie');"
REMOTE

echo "[deploy] Syncing repository to ${SSH_USER}@${HOST}:${REMOTE_ROOT}/rewrite"
DISPLAY=:0 \
SSH_ASKPASS="${ASKPASS_SCRIPT}" \
SSH_ASKPASS_REQUIRE=force \
SSH_PASSWORD="${SSH_PASSWORD}" \
setsid -w rsync -az --delete \
  --exclude '.git/' \
  --exclude '.phpunit.cache/' \
  --exclude '.remote_vuln_lab_runtime/' \
  --exclude 'testing_container_config.json' \
  -e "${RSYNC_SSH_CMD}" \
  "${ROOT_DIR}/" "${SSH_USER}@${HOST}:${REMOTE_ROOT}/rewrite/"

echo "[deploy] Installing composer dependencies on remote"
ssh_exec "cd ${REMOTE_ROOT}/rewrite && composer install --no-interaction --prefer-dist"

echo "[deploy] Building extension and starting vulnerable lab apps"
ssh_exec "cd ${REMOTE_ROOT}/rewrite && PHP_TAINT_TRACE_LAB_PHP_BIN=php${LAB_PHP_SERIES} PHP_TAINT_TRACE_LAB_PHP_CONFIG_BIN=php-config${LAB_PHP_SERIES} bash scripts/build_xmark_extension.sh && PHP_TAINT_TRACE_LAB_PHP_BIN=php${LAB_PHP_SERIES} PHP_TAINT_TRACE_LAB_PHP_CONFIG_BIN=php-config${LAB_PHP_SERIES} bash scripts/remote_vuln_lab_manage.sh profile ${EXTENSION_PROFILE} && PHP_TAINT_TRACE_LAB_PHP_BIN=php${LAB_PHP_SERIES} PHP_TAINT_TRACE_LAB_PHP_CONFIG_BIN=php-config${LAB_PHP_SERIES} PHP_TAINT_TRACE_LAB_EXTENSION_PROFILE=${EXTENSION_PROFILE} bash scripts/remote_vuln_lab_manage.sh restart && PHP_TAINT_TRACE_LAB_PHP_BIN=php${LAB_PHP_SERIES} PHP_TAINT_TRACE_LAB_PHP_CONFIG_BIN=php-config${LAB_PHP_SERIES} PHP_TAINT_TRACE_LAB_EXTENSION_PROFILE=${EXTENSION_PROFILE} bash scripts/remote_vuln_lab_manage.sh status && PHP_TAINT_TRACE_LAB_PHP_BIN=php${LAB_PHP_SERIES} PHP_TAINT_TRACE_LAB_PHP_CONFIG_BIN=php-config${LAB_PHP_SERIES} PHP_TAINT_TRACE_LAB_EXTENSION_PROFILE=${EXTENSION_PROFILE} bash scripts/remote_vuln_lab_manage.sh capabilities --json"

cat <<EOF
[deploy] Complete.

Remote host: ${HOST}
Remote project root: ${REMOTE_ROOT}/rewrite
Extension profile: ${EXTENSION_PROFILE}
Lab endpoints:
  XSS  : http://${HOST}:19081/
  RCE  : http://${HOST}:19082/
  FILE : http://${HOST}:19083/
  SSRF : http://${HOST}:19084/
  SQLI : http://${HOST}:19085/
  IDOR : http://${HOST}:19086/
  XXE  : http://${HOST}:19087/

Run verification:
  bash scripts/run_remote_vuln_lab_tests.sh --config ${CONFIG_PATH} --host-label ${HOST_LABEL} --remote-root ${REMOTE_ROOT} --extension-profile ${EXTENSION_PROFILE}
  bash scripts/run_remote_verifier_tests.sh --config ${CONFIG_PATH} --host-label ${HOST_LABEL} --remote-root ${REMOTE_ROOT} --extension-profile ${EXTENSION_PROFILE}
  bash scripts/run_remote_dead_letter_recovery_cycle.sh --config ${CONFIG_PATH} --host-label ${HOST_LABEL} --remote-root ${REMOTE_ROOT} --summary-only
  bash scripts/run_remote_dead_letter_recovery_campaign.sh --config ${CONFIG_PATH} --host-label ${HOST_LABEL} --remote-root ${REMOTE_ROOT}

Optional browser-aware XSS canary prep/run:
  bash scripts/prepare_remote_browser_probe.sh --config ${CONFIG_PATH} --host-label ${HOST_LABEL} --remote-root ${REMOTE_ROOT}
  bash scripts/run_remote_browser_xss_canary.sh --config ${CONFIG_PATH} --host-label ${HOST_LABEL} --remote-root ${REMOTE_ROOT}
  bash scripts/run_remote_browser_xss_soak.sh --config ${CONFIG_PATH} --host-label ${HOST_LABEL} --remote-root ${REMOTE_ROOT}
EOF
