#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v php-config >/dev/null 2>&1; then
  echo "php-config not found. Install php-dev/php-config first." >&2
  exit 1
fi

EXT_DIR="$(php-config --extension-dir)"
OPCACHE_SO="${EXT_DIR}/opcache.so"
if [[ ! -f "${OPCACHE_SO}" ]]; then
  echo "opcache.so not found at ${OPCACHE_SO}" >&2
  exit 1
fi

export PHP_TAINT_TRACE_SMOKE_EXTRA_PHP_ARGS="-d zend_extension=${OPCACHE_SO} -d opcache.enable=1 -d opcache.enable_cli=1 -d opcache.validate_timestamps=1 -d opcache.jit_buffer_size=64M -d opcache.jit=1205"
bash "${ROOT_DIR}/scripts/run_native_auto_prepend_smoke.sh"
