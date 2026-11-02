#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

append_csv_flag_args() {
  local csv="${1:-}"
  local flag="${2:?missing flag}"
  local -n output_ref="${3:?missing output array reference}"

  if [[ -z "${csv}" ]]; then
    return
  fi

  IFS=',' read -r -a _entries <<< "${csv}"
  for entry in "${_entries[@]}"; do
    local entry_trimmed
    entry_trimmed="$(echo "${entry}" | xargs)"
    if [[ -z "${entry_trimmed}" ]]; then
      continue
    fi
    output_ref+=("${flag}" "${entry_trimmed}")
  done
}

EXPECTED_FORMULA_VERSION="${PHP_TAINT_TRACE_EXPECTED_FORMULA_VERSION:-phase_c_v1_step27}"
METRICS_BASELINE_PATH="${PHP_TAINT_TRACE_METRICS_BASELINE_PATH:-tests/fixtures/verification_metrics_baseline.json}"
DRIFT_DEAD_LETTER_RATE_DELTA_THRESHOLD="${PHP_TAINT_TRACE_GATE_DRIFT_DEAD_LETTER_RATE_DELTA_THRESHOLD:-0.02}"
DEAD_LETTER_REASON_MAX_COUNTS_CSV="${PHP_TAINT_TRACE_GATE_DEAD_LETTER_REASON_MAX_COUNTS:-}"
DRIFT_DEAD_LETTER_REASON_RATE_THRESHOLDS_CSV="${PHP_TAINT_TRACE_GATE_DRIFT_DEAD_LETTER_REASON_RATE_THRESHOLDS:-}"

METRICS_EXTRA_ARGS=()
append_csv_flag_args "${DEAD_LETTER_REASON_MAX_COUNTS_CSV}" "--dead-letter-reason-max-count" METRICS_EXTRA_ARGS
append_csv_flag_args "${DRIFT_DEAD_LETTER_REASON_RATE_THRESHOLDS_CSV}" "--drift-dead-letter-reason-rate-threshold" METRICS_EXTRA_ARGS

echo "[gate] composer lint"
composer lint

echo "[gate] composer test"
composer test

echo "[gate] local verifier corpus run"
bash scripts/run_local_verifier_corpus.sh

echo "[gate] false-positive challenge corpus run"
composer corpus:false-positive-challenges

echo "[gate] false-positive matrix corpus run"
composer corpus:false-positive-matrix

echo "[gate] verifier metrics (unexpected confirmed + formula version + drift gate)"
bash scripts/report_verification_metrics.sh \
  --fail-on-unexpected-confirmed \
  --expected-formula-version "${EXPECTED_FORMULA_VERSION}" \
  --fail-on-formula-version-drift \
  --baseline "${METRICS_BASELINE_PATH}" \
  --drift-dead-letter-rate-delta-threshold "${DRIFT_DEAD_LETTER_RATE_DELTA_THRESHOLD}" \
  "${METRICS_EXTRA_ARGS[@]}" \
  --fail-on-drift

if [[ "${PHP_TAINT_TRACE_GATE_ENABLE_REMOTE_EXTENSION_PROFILE:-0}" == "1" ]]; then
  REMOTE_CONFIG_PATH="${PHP_TAINT_TRACE_GATE_REMOTE_CONFIG_PATH:-testing_container_config.json}"
  REMOTE_HOST_LABEL="${PHP_TAINT_TRACE_GATE_REMOTE_HOST_LABEL:-lab.example.invalid}"
  REMOTE_ROOT="${PHP_TAINT_TRACE_GATE_REMOTE_ROOT:-/opt/php_taint_trace_vuln_lab}"
  REMOTE_EXTENSION_PROFILE="${PHP_TAINT_TRACE_GATE_REMOTE_EXTENSION_PROFILE:-extended_all}"
  REMOTE_EXTENSION_STRICT="${PHP_TAINT_TRACE_GATE_REMOTE_EXTENSION_STRICT:-1}"

  STRICT_ARGS=()
  if [[ "${REMOTE_EXTENSION_STRICT}" == "1" ]]; then
    STRICT_ARGS+=(--strict-extension-profile)
  fi

  echo "[gate] remote extension-profile deploy (${REMOTE_EXTENSION_PROFILE}, strict=${REMOTE_EXTENSION_STRICT})"
  bash scripts/deploy_remote_vuln_lab.sh \
    --config "${REMOTE_CONFIG_PATH}" \
    --host-label "${REMOTE_HOST_LABEL}" \
    --remote-root "${REMOTE_ROOT}" \
    --profile "${REMOTE_EXTENSION_PROFILE}"

  echo "[gate] remote detector extension-profile assertions"
  bash scripts/run_remote_vuln_lab_tests.sh \
    --config "${REMOTE_CONFIG_PATH}" \
    --host-label "${REMOTE_HOST_LABEL}" \
    --remote-root "${REMOTE_ROOT}" \
    --extension-profile "${REMOTE_EXTENSION_PROFILE}" \
    "${STRICT_ARGS[@]}"

  echo "[gate] remote verifier extension-profile assertions"
  bash scripts/run_remote_verifier_tests.sh \
    --config "${REMOTE_CONFIG_PATH}" \
    --host-label "${REMOTE_HOST_LABEL}" \
    --remote-root "${REMOTE_ROOT}" \
    --extension-profile "${REMOTE_EXTENSION_PROFILE}" \
    "${STRICT_ARGS[@]}"
fi

if [[ "${PHP_TAINT_TRACE_GATE_ENABLE_REMOTE_BROWSER_CANARY:-0}" == "1" ]]; then
  REMOTE_CONFIG_PATH="${PHP_TAINT_TRACE_GATE_REMOTE_CONFIG_PATH:-testing_container_config.json}"
  REMOTE_HOST_LABEL="${PHP_TAINT_TRACE_GATE_REMOTE_HOST_LABEL:-lab.example.invalid}"
  REMOTE_ROOT="${PHP_TAINT_TRACE_GATE_REMOTE_ROOT:-/opt/php_taint_trace_vuln_lab}"
  XSS_BROWSER_MODE="${PHP_TAINT_TRACE_GATE_XSS_BROWSER_MODE:-advisory}"
  XSS_BROWSER_TIMEOUT_MS="${PHP_TAINT_TRACE_GATE_XSS_BROWSER_TIMEOUT_MS:-8000}"
  DEFAULT_XSS_BROWSER_DRIVER_CMD="node ${REMOTE_ROOT}/rewrite/scripts/xss_browser_probe_driver_playwright.mjs --url {url} --nonce {nonce} --timeout-ms {timeout_ms}"
  XSS_BROWSER_DRIVER_CMD="${PHP_TAINT_TRACE_GATE_XSS_BROWSER_DRIVER_CMD:-}"
  if [[ -z "${XSS_BROWSER_DRIVER_CMD}" ]]; then
    XSS_BROWSER_DRIVER_CMD="${DEFAULT_XSS_BROWSER_DRIVER_CMD}"
  fi
  XSS_BROWSER_VALIDATE_EXECUTION="${PHP_TAINT_TRACE_GATE_VALIDATE_XSS_BROWSER_EXECUTION_CONFIRMED:-1}"
  XSS_BROWSER_REQUIRE_READINESS="${PHP_TAINT_TRACE_GATE_REQUIRE_XSS_BROWSER_READINESS:-1}"
  XSS_BROWSER_MAX_FAILURE_RATE="${PHP_TAINT_TRACE_GATE_XSS_BROWSER_ADVISORY_MAX_FAILURE_RATE:-0.0}"
  XSS_BROWSER_MAX_UNCONFIGURED_RATE="${PHP_TAINT_TRACE_GATE_XSS_BROWSER_ADVISORY_MAX_UNCONFIGURED_RATE:-0.0}"
  XSS_BROWSER_MAX_DEAD_LETTERS="${PHP_TAINT_TRACE_GATE_MAX_DEAD_LETTERS:-0}"

  if [[ "${PHP_TAINT_TRACE_GATE_PREPARE_REMOTE_BROWSER_PROBE:-0}" == "1" ]]; then
    echo "[gate] preparing remote browser probe runtime"
    PREPARE_ARGS=(
      --config "${REMOTE_CONFIG_PATH}"
      --host-label "${REMOTE_HOST_LABEL}"
      --remote-root "${REMOTE_ROOT}"
    )
    if [[ "${PHP_TAINT_TRACE_GATE_PREPARE_INSTALL_CHROMIUM:-0}" == "1" ]]; then
      PREPARE_ARGS+=(--install-chromium)
    fi
    bash scripts/prepare_remote_browser_probe.sh "${PREPARE_ARGS[@]}"
  fi

  echo "[gate] remote browser-aware xss canary (${XSS_BROWSER_MODE})"
  bash scripts/run_remote_browser_xss_canary.sh \
    --config "${REMOTE_CONFIG_PATH}" \
    --host-label "${REMOTE_HOST_LABEL}" \
    --remote-root "${REMOTE_ROOT}" \
    --xss-browser-mode "${XSS_BROWSER_MODE}" \
    --xss-browser-timeout-ms "${XSS_BROWSER_TIMEOUT_MS}" \
    --xss-browser-driver-cmd "${XSS_BROWSER_DRIVER_CMD}" \
    --validate-xss-browser-execution-confirmed "${XSS_BROWSER_VALIDATE_EXECUTION}" \
    --require-xss-browser-readiness "${XSS_BROWSER_REQUIRE_READINESS}" \
    --xss-browser-advisory-max-failure-rate "${XSS_BROWSER_MAX_FAILURE_RATE}" \
    --xss-browser-advisory-max-unconfigured-rate "${XSS_BROWSER_MAX_UNCONFIGURED_RATE}" \
    --max-dead-letters "${XSS_BROWSER_MAX_DEAD_LETTERS}"

  if [[ "${PHP_TAINT_TRACE_GATE_ENABLE_REMOTE_BROWSER_SOAK:-0}" == "1" ]]; then
    SOAK_ITERATIONS="${PHP_TAINT_TRACE_GATE_REMOTE_BROWSER_SOAK_ITERATIONS:-5}"
    SOAK_MAX_FAILURES="${PHP_TAINT_TRACE_GATE_REMOTE_BROWSER_SOAK_MAX_FAILURES:-0}"
    SOAK_SLEEP_SECONDS="${PHP_TAINT_TRACE_GATE_REMOTE_BROWSER_SOAK_SLEEP_SECONDS:-1}"
    echo "[gate] remote browser-aware xss soak (iterations=${SOAK_ITERATIONS} max_failures=${SOAK_MAX_FAILURES})"
    bash scripts/run_remote_browser_xss_soak.sh \
      --config "${REMOTE_CONFIG_PATH}" \
      --host-label "${REMOTE_HOST_LABEL}" \
      --remote-root "${REMOTE_ROOT}" \
      --iterations "${SOAK_ITERATIONS}" \
      --sleep-seconds "${SOAK_SLEEP_SECONDS}" \
      --max-failures "${SOAK_MAX_FAILURES}" \
      --xss-browser-mode "${XSS_BROWSER_MODE}" \
      --xss-browser-timeout-ms "${XSS_BROWSER_TIMEOUT_MS}" \
      --xss-browser-driver-cmd "${XSS_BROWSER_DRIVER_CMD}" \
      --validate-xss-browser-execution-confirmed "${XSS_BROWSER_VALIDATE_EXECUTION}" \
      --require-xss-browser-readiness "${XSS_BROWSER_REQUIRE_READINESS}" \
      --xss-browser-advisory-max-failure-rate "${XSS_BROWSER_MAX_FAILURE_RATE}" \
      --xss-browser-advisory-max-unconfigured-rate "${XSS_BROWSER_MAX_UNCONFIGURED_RATE}" \
      --max-dead-letters "${XSS_BROWSER_MAX_DEAD_LETTERS}"
  fi
fi

if [[ "${PHP_TAINT_TRACE_GATE_ENABLE_REMOTE_DEAD_LETTER_CAMPAIGN:-0}" == "1" ]]; then
  REMOTE_CONFIG_PATH="${PHP_TAINT_TRACE_GATE_REMOTE_CONFIG_PATH:-testing_container_config.json}"
  REMOTE_HOST_LABEL="${PHP_TAINT_TRACE_GATE_REMOTE_HOST_LABEL:-lab.example.invalid}"
  REMOTE_ROOT="${PHP_TAINT_TRACE_GATE_REMOTE_ROOT:-/opt/php_taint_trace_vuln_lab}"
  CAMPAIGN_MAX_ROUNDS="${PHP_TAINT_TRACE_GATE_DEAD_LETTER_CAMPAIGN_MAX_ROUNDS:-5}"
  CAMPAIGN_MAX_STALL_ROUNDS="${PHP_TAINT_TRACE_GATE_DEAD_LETTER_CAMPAIGN_MAX_STALL_ROUNDS:-1}"
  CAMPAIGN_MAX_REQUEUE="${PHP_TAINT_TRACE_GATE_DEAD_LETTER_CAMPAIGN_MAX_REQUEUE:-0}"
  CAMPAIGN_WORKER_MAX_RUNS="${PHP_TAINT_TRACE_GATE_DEAD_LETTER_CAMPAIGN_WORKER_MAX_RUNS:-25}"
  CAMPAIGN_WORKER_BATCH_SIZE="${PHP_TAINT_TRACE_GATE_DEAD_LETTER_CAMPAIGN_WORKER_BATCH_SIZE:-50}"
  CAMPAIGN_WORKER_SLEEP_MS="${PHP_TAINT_TRACE_GATE_DEAD_LETTER_CAMPAIGN_WORKER_SLEEP_MS:-200}"
  CAMPAIGN_REQUEUE_TAG_PREFIX="${PHP_TAINT_TRACE_GATE_DEAD_LETTER_CAMPAIGN_REQUEUE_TAG_PREFIX:-gate_dead_letter_campaign_$(date -u +%Y%m%dT%H%M%SZ)}"
  CAMPAIGN_INCLUDE_REQUEUED="${PHP_TAINT_TRACE_GATE_DEAD_LETTER_CAMPAIGN_INCLUDE_REQUEUED_JOBS:-0}"
  CAMPAIGN_VERIFY_AFTER="${PHP_TAINT_TRACE_GATE_DEAD_LETTER_CAMPAIGN_VERIFY_AFTER:-0}"
  CAMPAIGN_REASON_CODES_CSV="${PHP_TAINT_TRACE_GATE_DEAD_LETTER_CAMPAIGN_REASON_CODES:-}"
  CAMPAIGN_JOB_IDS_CSV="${PHP_TAINT_TRACE_GATE_DEAD_LETTER_CAMPAIGN_JOB_IDS:-}"

  CAMPAIGN_ARGS=(
    --config "${REMOTE_CONFIG_PATH}"
    --host-label "${REMOTE_HOST_LABEL}"
    --remote-root "${REMOTE_ROOT}"
    --max-rounds "${CAMPAIGN_MAX_ROUNDS}"
    --max-stall-rounds "${CAMPAIGN_MAX_STALL_ROUNDS}"
    --max "${CAMPAIGN_MAX_REQUEUE}"
    --worker-max-runs "${CAMPAIGN_WORKER_MAX_RUNS}"
    --worker-batch-size "${CAMPAIGN_WORKER_BATCH_SIZE}"
    --worker-sleep-ms "${CAMPAIGN_WORKER_SLEEP_MS}"
    --requeue-tag-prefix "${CAMPAIGN_REQUEUE_TAG_PREFIX}"
  )
  if [[ "${CAMPAIGN_INCLUDE_REQUEUED}" == "1" ]]; then
    CAMPAIGN_ARGS+=(--include-requeued-jobs)
  fi
  if [[ "${CAMPAIGN_VERIFY_AFTER}" == "1" ]]; then
    CAMPAIGN_ARGS+=(--verify-after-campaign)
  fi
  append_csv_flag_args "${CAMPAIGN_REASON_CODES_CSV}" "--reason-code" CAMPAIGN_ARGS
  append_csv_flag_args "${CAMPAIGN_JOB_IDS_CSV}" "--job-id" CAMPAIGN_ARGS

  echo "[gate] remote dead-letter recovery campaign"
  bash scripts/run_remote_dead_letter_recovery_campaign.sh "${CAMPAIGN_ARGS[@]}"
fi

echo "[gate] build xmark extension"
bash ./scripts/build_xmark_extension.sh

echo "[gate] native auto-prepend smoke"
composer smoke:native-auto-prepend

echo "[gate] native auto-prepend smoke (opcode safe profile)"
PHP_TAINT_TRACE_ENABLE_OPCODE_HOOKS=1 composer smoke:native-auto-prepend

echo "[gate] native opcache/jit smoke"
composer smoke:native-opcache

echo "[gate] native soak smoke"
PHP_TAINT_TRACE_SOAK_REQUESTS=120 PHP_TAINT_TRACE_SOAK_CONCURRENCY=12 composer soak:native

echo "[gate] native soak smoke (opcode safe profile)"
PHP_TAINT_TRACE_ENABLE_OPCODE_HOOKS=1 PHP_TAINT_TRACE_SOAK_REQUESTS=80 PHP_TAINT_TRACE_SOAK_CONCURRENCY=8 composer soak:native

echo "[gate] native auto-prepend smoke (opcode full profile)"
PHP_TAINT_TRACE_ENABLE_OPCODE_HOOKS=1 PHP_TAINT_TRACE_OPCODE_HOOK_PROFILE=full composer smoke:native-auto-prepend

echo "[gate] native soak smoke (opcode full profile)"
PHP_TAINT_TRACE_ENABLE_OPCODE_HOOKS=1 PHP_TAINT_TRACE_OPCODE_HOOK_PROFILE=full PHP_TAINT_TRACE_SOAK_REQUESTS=80 PHP_TAINT_TRACE_SOAK_CONCURRENCY=8 composer soak:native

echo "[gate] native opcache/jit soak smoke"
PHP_TAINT_TRACE_SOAK_REQUESTS=120 PHP_TAINT_TRACE_SOAK_CONCURRENCY=12 composer soak:native-opcache

echo "[gate] native opcache/jit soak smoke (opcode full profile)"
PHP_TAINT_TRACE_ENABLE_OPCODE_HOOKS=1 PHP_TAINT_TRACE_OPCODE_HOOK_PROFILE=full PHP_TAINT_TRACE_SOAK_REQUESTS=80 PHP_TAINT_TRACE_SOAK_CONCURRENCY=8 composer soak:native-opcache

echo "[gate] release validation passed"
