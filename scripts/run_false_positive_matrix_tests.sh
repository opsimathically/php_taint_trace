#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME_DIR="${ROOT_DIR}/.php_taint_trace_runtime/verifier_false_positive_matrix"
CORPUS_DIR="${ROOT_DIR}/.php_taint_trace_runtime/verifier_false_positive_matrix_corpus"
METRICS_OUTPUT="${RUNTIME_DIR}/metrics.json"
BASE_PORT=18280
CALLBACK_PORT=18281

usage() {
  cat <<'USAGE'
Usage: scripts/run_false_positive_matrix_tests.sh [--runtime-dir PATH] [--corpus-dir PATH] [--metrics-output PATH] [--base-port PORT] [--callback-port PORT]

Builds and validates a generated adversarial replay-shape matrix:
- method shapes: GET-query, POST-query, POST-body (where supported),
- scenario kinds: safe and vulnerable,
- categories: rce/ssrf/sqli/file/xss/idor.

The script fails on any false positives/false negatives, decision-tier drift, outcome drift, or coverage gaps.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --runtime-dir)
      RUNTIME_DIR="$2"
      shift 2
      ;;
    --corpus-dir)
      CORPUS_DIR="$2"
      shift 2
      ;;
    --metrics-output)
      METRICS_OUTPUT="$2"
      shift 2
      ;;
    --base-port)
      BASE_PORT="$2"
      shift 2
      ;;
    --callback-port)
      CALLBACK_PORT="$2"
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

mkdir -p "${RUNTIME_DIR}"
if [[ "${CORPUS_DIR}" == "${RUNTIME_DIR}" || "${CORPUS_DIR}" == "${RUNTIME_DIR}/"* ]]; then
  echo "[fp-matrix] corpus dir must not be nested under runtime dir: ${CORPUS_DIR}" >&2
  exit 1
fi
rm -rf "${CORPUS_DIR}"
mkdir -p "${CORPUS_DIR}"

php "${ROOT_DIR}/scripts/generate_false_positive_matrix_corpus.php" \
  --corpus-dir "${CORPUS_DIR}"

echo "[fp-matrix] running local verifier corpus with generated matrix"
bash "${ROOT_DIR}/scripts/run_local_verifier_corpus.sh" \
  --runtime-dir "${RUNTIME_DIR}" \
  --corpus-dir "${CORPUS_DIR}" \
  --base-port "${BASE_PORT}" \
  --callback-port "${CALLBACK_PORT}"

echo "[fp-matrix] building metrics"
bash "${ROOT_DIR}/scripts/report_verification_metrics.sh" \
  --runtime-dir "${RUNTIME_DIR}" \
  --corpus-dir "${CORPUS_DIR}" \
  --output "${METRICS_OUTPUT}" \
  --fail-on-unexpected-confirmed \
  --expected-formula-version phase_c_v1_step27 \
  --fail-on-formula-version-drift

php "${ROOT_DIR}/scripts/validate_false_positive_suite_metrics.php" \
  --mode matrix \
  --metrics "${METRICS_OUTPUT}" \
  --corpus-dir "${CORPUS_DIR}"

echo "[fp-matrix] metrics: ${METRICS_OUTPUT}"
echo "[fp-matrix] complete"
