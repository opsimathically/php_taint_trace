#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXT_DIR="${ROOT_DIR}/ext/xmark"

PHP_BIN="${PHP_TAINT_TRACE_LAB_PHP_BIN:-php}"
PHPIZE_BIN="${PHP_TAINT_TRACE_LAB_PHPIZE_BIN:-}"
PHP_CONFIG_BIN="${PHP_TAINT_TRACE_LAB_PHP_CONFIG_BIN:-}"

if [[ -z "${PHPIZE_BIN}" ]]; then
  if [[ "${PHP_BIN}" =~ ^php([0-9]+\.[0-9]+)$ ]] && command -v "phpize${BASH_REMATCH[1]}" >/dev/null 2>&1; then
    PHPIZE_BIN="phpize${BASH_REMATCH[1]}"
  else
    PHPIZE_BIN="phpize"
  fi
fi

if [[ -z "${PHP_CONFIG_BIN}" ]]; then
  if [[ "${PHP_BIN}" =~ ^php([0-9]+\.[0-9]+)$ ]] && command -v "php-config${BASH_REMATCH[1]}" >/dev/null 2>&1; then
    PHP_CONFIG_BIN="php-config${BASH_REMATCH[1]}"
  else
    PHP_CONFIG_BIN="php-config"
  fi
fi

if ! command -v "${PHPIZE_BIN}" >/dev/null 2>&1; then
  echo "${PHPIZE_BIN} not found. Install php-dev/phpize first." >&2
  exit 1
fi

if ! command -v "${PHP_CONFIG_BIN}" >/dev/null 2>&1; then
  echo "${PHP_CONFIG_BIN} not found. Install php-dev/php-config first." >&2
  exit 1
fi

INSTALL=0
if [[ "${1:-}" == "--install" ]]; then
  INSTALL=1
fi

pushd "${EXT_DIR}" >/dev/null
"${PHPIZE_BIN}" --clean >/dev/null 2>&1 || true
rm -rf .libs modules autom4te.cache build
rm -f Makefile config.cache config.h config.h.in config.log config.nice config.status configure libtool run-tests.php
rm -f ./*.dep ./*.lo ./*.o ./*.la
"${PHPIZE_BIN}"
./configure --with-php-config="$(command -v "${PHP_CONFIG_BIN}")" --enable-xmark
make -j"$(nproc)"

if [[ ${INSTALL} -eq 1 ]]; then
  sudo make install
fi
popd >/dev/null

echo "Built extension in ${EXT_DIR}/modules/xmark.so"
if [[ ${INSTALL} -eq 1 ]]; then
  echo "Installed extension. Add 'extension=xmark.so' to your active php.ini."
fi
