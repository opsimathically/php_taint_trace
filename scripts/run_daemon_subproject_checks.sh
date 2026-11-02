#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'USAGE'
Usage: scripts/run_daemon_subproject_checks.sh

Runs lint/test/build checks for daemon-oriented Node.js subprojects:
  - subprojects/vulnerability_visualizer_ui_daemon
  - subprojects/nodejs_php_dbgp_client_sdk
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if ! command -v npm >/dev/null 2>&1; then
  echo "Missing required command: npm" >&2
  exit 1
fi

projects=(
  "subprojects/vulnerability_visualizer_ui_daemon"
  "subprojects/nodejs_php_dbgp_client_sdk"
)

for rel in "${projects[@]}"; do
  abs="${ROOT_DIR}/${rel}"
  if [[ ! -d "${abs}" ]]; then
    echo "Missing project directory: ${abs}" >&2
    exit 1
  fi

  echo "[daemon-checks] ${rel}: npm ci"
  npm --prefix "${abs}" ci

  echo "[daemon-checks] ${rel}: npm run lint"
  npm --prefix "${abs}" run lint

  echo "[daemon-checks] ${rel}: npm run test"
  npm --prefix "${abs}" run test

  echo "[daemon-checks] ${rel}: npm run build"
  npm --prefix "${abs}" run build
done

echo "[daemon-checks] PASS"
