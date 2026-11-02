#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_PATH="${ROOT_DIR}/config/verifier.example.json"
TARGET_PATH="/etc/php_taint_trace/verifier.json"

usage() {
  cat <<'USAGE'
Usage: scripts/install_verifier_config.sh [--source PATH] [--target PATH]

Installs verifier worker config for VerifierRuntimeConfig::fromEnvironment().
Default target is /etc/php_taint_trace/verifier.json.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source)
      SOURCE_PATH="$2"
      shift 2
      ;;
    --target)
      TARGET_PATH="$2"
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

if [[ ! -f "${SOURCE_PATH}" ]]; then
  echo "Source config file not found: ${SOURCE_PATH}" >&2
  exit 1
fi

TARGET_DIR="$(dirname "${TARGET_PATH}")"

if [[ -w "${TARGET_DIR}" || (! -e "${TARGET_DIR}" && -w "$(dirname "${TARGET_DIR}")") ]]; then
  mkdir -p "${TARGET_DIR}"
  cp "${SOURCE_PATH}" "${TARGET_PATH}"
  echo "Installed verifier config at ${TARGET_PATH}"
  exit 0
fi

if ! command -v sudo >/dev/null 2>&1; then
  echo "Target directory requires elevated permissions and sudo is unavailable." >&2
  exit 1
fi

sudo mkdir -p "${TARGET_DIR}"
sudo cp "${SOURCE_PATH}" "${TARGET_PATH}"
echo "Installed verifier config at ${TARGET_PATH} (via sudo)"

