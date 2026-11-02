#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_PATH="${PHP_TAINT_TRACE_TEST_CONFIG:-${XDG_CONFIG_HOME:-${HOME}/.config}/php_taint_trace/testing_container_config.json}"
HOST_LABEL="${PHP_TAINT_TRACE_TEST_HOST_LABEL:-lab.example.invalid}"

usage() {
  cat <<'EOF'
Usage: scripts/bootstrap_test_container.sh [--config PATH] [--host-label LABEL]

Reads SSH and sudo credentials from testing_container_config.json, connects to the
test container, installs full rewrite tooling, and ensures php-src branch checkouts
exist under /opt/php-src-worktrees.
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

if [[ ! -f "${CONFIG_PATH}" ]]; then
  echo "Config file not found: ${CONFIG_PATH}" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required on the local machine." >&2
  exit 1
fi

if ! command -v ssh >/dev/null 2>&1; then
  echo "ssh is required on the local machine." >&2
  exit 1
fi

if ! command -v setsid >/dev/null 2>&1; then
  echo "setsid is required on the local machine." >&2
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

REMOTE_CMD="$(printf "SUDOPASS=%q REMOTE_USER=%q bash -s" "$SUDO_PASSWORD" "$SSH_USER")"

DISPLAY=:0 \
SSH_ASKPASS="${ASKPASS_SCRIPT}" \
SSH_ASKPASS_REQUIRE=force \
SSH_PASSWORD="${SSH_PASSWORD}" \
setsid -w ssh "${SSH_OPTS[@]}" "${SSH_USER}@${HOST}" "${REMOTE_CMD}" <<'REMOTE'
set -euo pipefail

run_sudo() {
  printf '%s\n' "$SUDOPASS" | sudo -S -k -p '' "$@"
}

run_sudo apt-get update

COMMON_CANDIDATES=(
  build-essential autoconf automake bison re2c pkg-config cmake ninja-build libtool m4 gperf byacc gettext
  git curl wget unzip zip xz-utils ca-certificates software-properties-common gnupg lsb-release jq
  gdb valgrind strace ltrace ccache clang llvm make patch rsync
  libxml2-dev libsqlite3-dev libssl-dev libcurl4-openssl-dev libonig-dev libzip-dev libreadline-dev
  libicu-dev libargon2-dev libsodium-dev libgmp-dev libtidy-dev libxslt1-dev libffi-dev libpq-dev
  libldap2-dev libkrb5-dev libjpeg-dev libpng-dev libwebp-dev libfreetype6-dev libavif-dev
  libenchant-2-dev libpspell-dev libc-client2007e-dev libedit-dev libbz2-dev zlib1g-dev liblz4-dev
  libzstd-dev
)

PHP_CANDIDATES=(
  php php-cli php-dev php-pear php-xml php-mbstring php-curl php-zip php-sqlite3 php-pgsql php-mysql
  php-gd php-opcache php-readline php-intl php-bcmath php-soap php-phpdbg php-xdebug phpunit composer
)

available_common=()
for pkg in "${COMMON_CANDIDATES[@]}"; do
  if apt-cache show "$pkg" >/dev/null 2>&1; then
    available_common+=("$pkg")
  fi
done

available_php=()
for pkg in "${PHP_CANDIDATES[@]}"; do
  if apt-cache show "$pkg" >/dev/null 2>&1; then
    available_php+=("$pkg")
  fi
done

if ((${#available_common[@]} > 0)); then
  run_sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y "${available_common[@]}"
fi

if ((${#available_php[@]} > 0)); then
  run_sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y "${available_php[@]}"
fi

run_sudo mkdir -p /opt/php-src-worktrees
run_sudo chown -R "$REMOTE_USER:$REMOTE_USER" /opt/php-src-worktrees

clone_branch() {
  local branch="$1"
  local dir_name="$2"
  local target="/opt/php-src-worktrees/${dir_name}"

  if [[ ! -d "${target}/.git" ]]; then
    git clone --depth 1 --filter=blob:none --single-branch --branch "$branch" \
      https://github.com/php/php-src.git "$target"
    return
  fi

  git -C "$target" fetch --depth 1 origin "$branch"
  git -C "$target" checkout -q "$branch" || true
  git -C "$target" reset --hard -q FETCH_HEAD
}

clone_branch PHP-8.1 php-8.1
clone_branch PHP-8.2 php-8.2
clone_branch PHP-8.3 php-8.3
clone_branch PHP-8.4 php-8.4
clone_branch master php-master

echo
echo "=== TOOLING SUMMARY ==="
php -v | head -n 2 || true
phpize -v | head -n 3 || true
php-config --version || true
composer --version || true
phpunit --version || true
gcc --version | head -n 1 || true
clang --version | head -n 1 || true
re2c --version || true
bison --version | head -n 1 || true

echo
echo "php-src branches:"
for d in /opt/php-src-worktrees/php-*; do
  [[ -d "$d/.git" ]] || continue
  branch="$(git -C "$d" branch --show-current 2>/dev/null || true)"
  sha="$(git -C "$d" rev-parse --short HEAD 2>/dev/null || true)"
  printf '%s\t%s\t%s\n' "$(basename "$d")" "$branch" "$sha"
done

echo
echo "Disk usage:"
du -sh /opt/php-src-worktrees || true
REMOTE
