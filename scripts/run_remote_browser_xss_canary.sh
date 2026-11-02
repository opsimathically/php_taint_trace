#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_PATH="${PHP_TAINT_TRACE_TEST_CONFIG:-${XDG_CONFIG_HOME:-${HOME}/.config}/php_taint_trace/testing_container_config.json}"
HOST_LABEL="${PHP_TAINT_TRACE_TEST_HOST_LABEL:-lab.example.invalid}"
REMOTE_ROOT="/opt/php_taint_trace_vuln_lab"
XSS_BROWSER_MODE="${PHP_TAINT_TRACE_REMOTE_XSS_BROWSER_MODE:-advisory}"
XSS_BROWSER_TIMEOUT_MS="${PHP_TAINT_TRACE_REMOTE_XSS_BROWSER_TIMEOUT_MS:-8000}"
XSS_BROWSER_DRIVER_CMD="${PHP_TAINT_TRACE_REMOTE_XSS_BROWSER_DRIVER_CMD:-}"
VALIDATE_XSS_BROWSER_EXECUTION_CONFIRMED="${PHP_TAINT_TRACE_REMOTE_VALIDATE_XSS_BROWSER_EXECUTION_CONFIRMED:-1}"
REQUIRE_XSS_BROWSER_READINESS="${PHP_TAINT_TRACE_REMOTE_REQUIRE_XSS_BROWSER_READINESS:-1}"
XSS_BROWSER_ADVISORY_MAX_FAILURE_RATE="${PHP_TAINT_TRACE_REMOTE_XSS_BROWSER_ADVISORY_MAX_FAILURE_RATE:-0.0}"
XSS_BROWSER_ADVISORY_MAX_UNCONFIGURED_RATE="${PHP_TAINT_TRACE_REMOTE_XSS_BROWSER_ADVISORY_MAX_UNCONFIGURED_RATE:-0.0}"
MAX_DEAD_LETTERS="${PHP_TAINT_TRACE_REMOTE_MAX_DEAD_LETTERS:-0}"

usage() {
  cat <<'USAGE'
Usage: scripts/run_remote_browser_xss_canary.sh [--config PATH] [--host-label LABEL] [--remote-root PATH]
                                                [--xss-browser-mode advisory|enforce]
                                                [--xss-browser-timeout-ms N]
                                                [--xss-browser-driver-cmd CMD]
                                                [--validate-xss-browser-execution-confirmed 0|1]
                                                [--require-xss-browser-readiness 0|1]
                                                [--xss-browser-advisory-max-failure-rate 0.0-1.0]
                                                [--xss-browser-advisory-max-unconfigured-rate 0.0-1.0]
                                                [--max-dead-letters N]

Runs remote verifier E2E with browser-aware XSS mode enabled and browser reason-code validation required.

Default mode is advisory.
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
    --xss-browser-mode)
      XSS_BROWSER_MODE="$2"
      shift 2
      ;;
    --xss-browser-timeout-ms)
      XSS_BROWSER_TIMEOUT_MS="$2"
      shift 2
      ;;
    --xss-browser-driver-cmd)
      XSS_BROWSER_DRIVER_CMD="$2"
      shift 2
      ;;
    --validate-xss-browser-execution-confirmed)
      VALIDATE_XSS_BROWSER_EXECUTION_CONFIRMED="$2"
      shift 2
      ;;
    --require-xss-browser-readiness)
      REQUIRE_XSS_BROWSER_READINESS="$2"
      shift 2
      ;;
    --xss-browser-advisory-max-failure-rate)
      XSS_BROWSER_ADVISORY_MAX_FAILURE_RATE="$2"
      shift 2
      ;;
    --xss-browser-advisory-max-unconfigured-rate)
      XSS_BROWSER_ADVISORY_MAX_UNCONFIGURED_RATE="$2"
      shift 2
      ;;
    --max-dead-letters)
      MAX_DEAD_LETTERS="$2"
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

if [[ -z "${XSS_BROWSER_DRIVER_CMD}" ]]; then
  XSS_BROWSER_DRIVER_CMD="node ${REMOTE_ROOT}/rewrite/scripts/xss_browser_probe_driver_playwright.mjs --url {url} --nonce {nonce} --timeout-ms {timeout_ms}"
fi

if [[ "${XSS_BROWSER_MODE}" == "off" ]]; then
  echo "Invalid browser canary mode: off. Use advisory or enforce." >&2
  exit 1
fi

bash "${ROOT_DIR}/scripts/run_remote_verifier_tests.sh" \
  --config "${CONFIG_PATH}" \
  --host-label "${HOST_LABEL}" \
  --remote-root "${REMOTE_ROOT}" \
  --xss-browser-mode "${XSS_BROWSER_MODE}" \
  --xss-browser-timeout-ms "${XSS_BROWSER_TIMEOUT_MS}" \
  --xss-browser-driver-cmd "${XSS_BROWSER_DRIVER_CMD}" \
  --validate-xss-browser-reason 1 \
  --validate-xss-browser-execution-confirmed "${VALIDATE_XSS_BROWSER_EXECUTION_CONFIRMED}" \
  --require-xss-browser-readiness "${REQUIRE_XSS_BROWSER_READINESS}" \
  --xss-browser-advisory-max-failure-rate "${XSS_BROWSER_ADVISORY_MAX_FAILURE_RATE}" \
  --xss-browser-advisory-max-unconfigured-rate "${XSS_BROWSER_ADVISORY_MAX_UNCONFIGURED_RATE}" \
  --max-dead-letters "${MAX_DEAD_LETTERS}"
