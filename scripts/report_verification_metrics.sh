#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME_DIR="${ROOT_DIR}/.php_taint_trace_runtime/verifier_corpus"
CORPUS_DIR="${ROOT_DIR}/tests/fixtures/verification_corpus"
OUTPUT_PATH="${RUNTIME_DIR}/metrics.json"
FAIL_ON_UNEXPECTED_CONFIRMED=0
EXPECTED_FORMULA_VERSION=""
FAIL_ON_FORMULA_VERSION_DRIFT=0
BASELINE_PATH=""
FAIL_ON_DRIFT=0
DRIFT_CONFIRMED_RATIO_DELTA_THRESHOLD="0.15"
DRIFT_REPLAY_FAILURE_RATE_DELTA_THRESHOLD="0.10"
DRIFT_REASON_DISTRIBUTION_L1_THRESHOLD="0.40"
DRIFT_XSS_BROWSER_EXEC_CONFIRMED_RATE_DROP_THRESHOLD="0.30"
DRIFT_XSS_BROWSER_FAILURE_RATE_DELTA_THRESHOLD="0.10"
DRIFT_XSS_BROWSER_UNCONFIGURED_RATE_DELTA_THRESHOLD="0.05"
DRIFT_DEAD_LETTER_RATE_DELTA_THRESHOLD="0.02"
DRIFT_EXTENSION_ASSERTION_SKIP_RATE_DELTA_THRESHOLD="0.15"
EXTENSION_ASSERTIONS_SUMMARY_PATH=""
SCENARIO_REQUIREMENTS_SUMMARY_PATH=""
DEAD_LETTER_REASON_MAX_COUNTS=()
DRIFT_DEAD_LETTER_REASON_RATE_THRESHOLDS=()

usage() {
  cat <<'USAGE'
Usage: scripts/report_verification_metrics.sh [--runtime-dir PATH] [--corpus-dir PATH] [--output PATH] [--fail-on-unexpected-confirmed] [--expected-formula-version VERSION] [--fail-on-formula-version-drift] [--baseline PATH] [--fail-on-drift] [--drift-confirmed-ratio-delta-threshold FLOAT] [--drift-replay-failure-rate-delta-threshold FLOAT] [--drift-reason-distribution-l1-threshold FLOAT] [--drift-xss-browser-exec-confirmed-rate-drop-threshold FLOAT] [--drift-xss-browser-failure-rate-delta-threshold FLOAT] [--drift-xss-browser-unconfigured-rate-delta-threshold FLOAT] [--drift-dead-letter-rate-delta-threshold FLOAT] [--drift-extension-assertion-skip-rate-delta-threshold FLOAT] [--extension-assertions-summary PATH] [--scenario-requirements-summary PATH] [--dead-letter-reason-max-count PREFIX=COUNT] [--drift-dead-letter-reason-rate-threshold PREFIX=FLOAT]

Builds verification metrics from corpus labels, verifier results, and decision artifacts.

Baseline snapshot example:
  bash scripts/report_verification_metrics.sh --output ai_documentation/baselines/metrics_$(date +%Y%m%d_%H%M%S).json

Strict gate example:
  bash scripts/report_verification_metrics.sh \
    --fail-on-unexpected-confirmed \
    --expected-formula-version phase_c_v1_step27 \
    --fail-on-formula-version-drift \
    --baseline tests/fixtures/verification_metrics_baseline.json \
    --fail-on-drift
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
    --output)
      OUTPUT_PATH="$2"
      shift 2
      ;;
    --fail-on-unexpected-confirmed)
      FAIL_ON_UNEXPECTED_CONFIRMED=1
      shift
      ;;
    --expected-formula-version)
      EXPECTED_FORMULA_VERSION="$2"
      shift 2
      ;;
    --fail-on-formula-version-drift)
      FAIL_ON_FORMULA_VERSION_DRIFT=1
      shift
      ;;
    --baseline)
      BASELINE_PATH="$2"
      shift 2
      ;;
    --fail-on-drift)
      FAIL_ON_DRIFT=1
      shift
      ;;
    --drift-confirmed-ratio-delta-threshold)
      DRIFT_CONFIRMED_RATIO_DELTA_THRESHOLD="$2"
      shift 2
      ;;
    --drift-replay-failure-rate-delta-threshold)
      DRIFT_REPLAY_FAILURE_RATE_DELTA_THRESHOLD="$2"
      shift 2
      ;;
    --drift-reason-distribution-l1-threshold)
      DRIFT_REASON_DISTRIBUTION_L1_THRESHOLD="$2"
      shift 2
      ;;
    --drift-xss-browser-exec-confirmed-rate-drop-threshold)
      DRIFT_XSS_BROWSER_EXEC_CONFIRMED_RATE_DROP_THRESHOLD="$2"
      shift 2
      ;;
    --drift-xss-browser-failure-rate-delta-threshold)
      DRIFT_XSS_BROWSER_FAILURE_RATE_DELTA_THRESHOLD="$2"
      shift 2
      ;;
    --drift-xss-browser-unconfigured-rate-delta-threshold)
      DRIFT_XSS_BROWSER_UNCONFIGURED_RATE_DELTA_THRESHOLD="$2"
      shift 2
      ;;
    --drift-dead-letter-rate-delta-threshold)
      DRIFT_DEAD_LETTER_RATE_DELTA_THRESHOLD="$2"
      shift 2
      ;;
    --drift-extension-assertion-skip-rate-delta-threshold)
      DRIFT_EXTENSION_ASSERTION_SKIP_RATE_DELTA_THRESHOLD="$2"
      shift 2
      ;;
    --extension-assertions-summary)
      EXTENSION_ASSERTIONS_SUMMARY_PATH="$2"
      shift 2
      ;;
    --scenario-requirements-summary)
      SCENARIO_REQUIREMENTS_SUMMARY_PATH="$2"
      shift 2
      ;;
    --dead-letter-reason-max-count)
      DEAD_LETTER_REASON_MAX_COUNTS+=("$2")
      shift 2
      ;;
    --drift-dead-letter-reason-rate-threshold)
      DRIFT_DEAD_LETTER_REASON_RATE_THRESHOLDS+=("$2")
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

for spec in "${DEAD_LETTER_REASON_MAX_COUNTS[@]}"; do
  if ! [[ "${spec}" =~ ^[^=]+=[0-9]+$ ]]; then
    echo "Invalid --dead-letter-reason-max-count: ${spec}. Expected PREFIX=COUNT." >&2
    exit 1
  fi
done

for spec in "${DRIFT_DEAD_LETTER_REASON_RATE_THRESHOLDS[@]}"; do
  if ! [[ "${spec}" =~ ^[^=]+=[0-9]+(\.[0-9]+)?$ ]]; then
    echo "Invalid --drift-dead-letter-reason-rate-threshold: ${spec}. Expected PREFIX=FLOAT." >&2
    exit 1
  fi
done

mkdir -p "$(dirname "${OUTPUT_PATH}")"

DEAD_LETTER_REASON_MAX_COUNTS_CSV="$(IFS=,; echo "${DEAD_LETTER_REASON_MAX_COUNTS[*]}")"
DRIFT_DEAD_LETTER_REASON_RATE_THRESHOLDS_CSV="$(IFS=,; echo "${DRIFT_DEAD_LETTER_REASON_RATE_THRESHOLDS[*]}")"

php -r '
$runtimeDir = $argv[1];
$corpusDir = $argv[2];
$outputPath = $argv[3];
$failOnUnexpectedConfirmed = ((int) $argv[4]) === 1;
$expectedFormulaVersion = trim((string) ($argv[5] ?? ""));
$failOnFormulaVersionDrift = ((int) ($argv[6] ?? 0)) === 1;
$baselinePath = trim((string) ($argv[7] ?? ""));
$failOnDrift = ((int) ($argv[8] ?? 0)) === 1;
$driftConfirmedRatioDeltaThreshold = (float) ($argv[9] ?? "0.15");
$driftReplayFailureRateDeltaThreshold = (float) ($argv[10] ?? "0.10");
$driftReasonDistributionL1Threshold = (float) ($argv[11] ?? "0.40");
$driftXssBrowserExecConfirmedRateDropThreshold = (float) ($argv[12] ?? "0.30");
$driftXssBrowserFailureRateDeltaThreshold = (float) ($argv[13] ?? "0.10");
$driftXssBrowserUnconfiguredRateDeltaThreshold = (float) ($argv[14] ?? "0.05");
$driftDeadLetterRateDeltaThreshold = (float) ($argv[15] ?? "0.02");
$driftExtensionAssertionSkipRateDeltaThreshold = (float) ($argv[16] ?? "0.15");
$extensionAssertionsSummaryPath = trim((string) ($argv[17] ?? ""));
$scenarioRequirementsSummaryPath = trim((string) ($argv[18] ?? ""));
$deadLetterReasonBudgetCsv = trim((string) ($argv[19] ?? ""));
$driftDeadLetterReasonRateThresholdsCsv = trim((string) ($argv[20] ?? ""));
$errors = array();

$deadLetterReasonBudgets = array();
if ($deadLetterReasonBudgetCsv !== "") {
    $parts = explode(",", $deadLetterReasonBudgetCsv);
    foreach ($parts as $part) {
        $spec = trim($part);
        if ($spec === "") {
            continue;
        }
        $chunks = explode("=", $spec, 2);
        if (count($chunks) !== 2) {
            $errors[] = "invalid dead-letter reason budget spec: " . $spec;
            continue;
        }
        $prefix = trim((string) $chunks[0]);
        $maxRaw = trim((string) $chunks[1]);
        if ($prefix === "" || !preg_match("/^\d+$/", $maxRaw)) {
            $errors[] = "invalid dead-letter reason budget spec: " . $spec;
            continue;
        }
        $deadLetterReasonBudgets[$prefix] = (int) $maxRaw;
    }
}

$driftDeadLetterReasonRateThresholds = array();
if ($driftDeadLetterReasonRateThresholdsCsv !== "") {
    $parts = explode(",", $driftDeadLetterReasonRateThresholdsCsv);
    foreach ($parts as $part) {
        $spec = trim($part);
        if ($spec === "") {
            continue;
        }
        $chunks = explode("=", $spec, 2);
        if (count($chunks) !== 2) {
            $errors[] = "invalid dead-letter reason rate drift threshold spec: " . $spec;
            continue;
        }
        $prefix = trim((string) $chunks[0]);
        $thresholdRaw = trim((string) $chunks[1]);
        if ($prefix === "" || !is_numeric($thresholdRaw)) {
            $errors[] = "invalid dead-letter reason rate drift threshold spec: " . $spec;
            continue;
        }
        $threshold = (float) $thresholdRaw;
        if ($threshold < 0.0 || $threshold > 1.0) {
            $errors[] = "dead-letter reason rate drift threshold out of range [0.0,1.0]: " . $spec;
            continue;
        }
        $driftDeadLetterReasonRateThresholds[$prefix] = $threshold;
    }
    ksort($driftDeadLetterReasonRateThresholds);
}

$allowedOutcomes = array("confirmed", "not_confirmed", "inconclusive", "blocked_by_policy", "replay_failed");
$allowedTiers = array("confirmed", "high_likelihood", "reachable_unverified", "suppressed", "invalid");
$allowedCategories = array("rce", "ssrf", "sqli", "file", "xss", "idor", "xxe");
$allowedScenarioKinds = array("vulnerable", "safe");

$scenarios = array();
$files = glob(rtrim($corpusDir, "/") . "/*.json");
if (!is_array($files) || $files === array()) {
    $errors[] = "verification corpus directory is empty: " . $corpusDir;
} else {
    sort($files);
    foreach ($files as $file) {
        $payload = json_decode((string) @file_get_contents($file), true);
        if (!is_array($payload)) {
            $errors[] = "invalid JSON in corpus file: " . $file;
            continue;
        }

        $scenarioId = (string) ($payload["scenario_id"] ?? "");
        $category = (string) ($payload["category"] ?? "");
        $scenarioKind = (string) ($payload["scenario_kind"] ?? "");
        $expectedConfirmedRaw = $payload["expected_confirmed"] ?? null;
        $expectedOutcome = (string) ($payload["expected_outcome"] ?? "");
        $expectedTier = (string) ($payload["expected_decision_tier"] ?? "");
        $endpoint = (string) ($payload["endpoint"] ?? "");
        $payloadPlan = is_array($payload["payload_plan"] ?? null) ? $payload["payload_plan"] : null;
        $targetParam = is_array($payloadPlan) ? (string) ($payloadPlan["target_query_param"] ?? "") : "";
        $targetBodyParam = is_array($payloadPlan) ? (string) ($payloadPlan["target_body_param"] ?? "") : "";
        $expectedReasonCodesAny = array();
        if (is_array($payload["expected_reason_codes_any"] ?? null)) {
            foreach ($payload["expected_reason_codes_any"] as $reasonCode) {
                if (is_scalar($reasonCode) && trim((string) $reasonCode) !== "") {
                    $expectedReasonCodesAny[] = trim((string) $reasonCode);
                }
            }
            $expectedReasonCodesAny = array_values(array_unique($expectedReasonCodesAny));
        } elseif (($payload["expected_reason_codes_any"] ?? null) !== null) {
            $errors[] = "expected_reason_codes_any must be an array in " . $file;
        }

        if ($scenarioId === "") {
            $errors[] = "missing scenario_id in " . $file;
        }
        if ($category === "" || !in_array($category, $allowedCategories, true)) {
            $errors[] = "invalid category in " . $file . ": " . $category;
        }
        if ($scenarioKind === "" || !in_array($scenarioKind, $allowedScenarioKinds, true)) {
            $errors[] = "invalid scenario_kind in " . $file . ": " . $scenarioKind;
        }
        if ($expectedOutcome === "" || !in_array($expectedOutcome, $allowedOutcomes, true)) {
            $errors[] = "invalid expected_outcome in " . $file . ": " . $expectedOutcome;
        }
        if ($expectedTier === "" || !in_array($expectedTier, $allowedTiers, true)) {
            $errors[] = "invalid expected_decision_tier in " . $file . ": " . $expectedTier;
        }
        if ($endpoint === "") {
            $errors[] = "missing endpoint in " . $file;
        }
        if ($targetParam === "" && $targetBodyParam === "") {
            $errors[] = "missing payload_plan target parameter (target_query_param or target_body_param) in " . $file;
        }
        if ($scenarioId !== "" && isset($scenarios[$scenarioId])) {
            $errors[] = "duplicate scenario_id in corpus: " . $scenarioId;
        }

        $expectedConfirmed = null;
        if (is_bool($expectedConfirmedRaw)) {
            $expectedConfirmed = $expectedConfirmedRaw;
        } elseif (is_string($expectedConfirmedRaw)) {
            $normalized = strtolower(trim($expectedConfirmedRaw));
            if (in_array($normalized, array("1", "true", "yes"), true)) {
                $expectedConfirmed = true;
            } elseif (in_array($normalized, array("0", "false", "no"), true)) {
                $expectedConfirmed = false;
            }
        } elseif (is_int($expectedConfirmedRaw)) {
            if ($expectedConfirmedRaw === 1) {
                $expectedConfirmed = true;
            } elseif ($expectedConfirmedRaw === 0) {
                $expectedConfirmed = false;
            }
        }
        if (!is_bool($expectedConfirmed)) {
            $errors[] = "invalid expected_confirmed in " . $file;
            $expectedConfirmed = false;
        }

        if ($scenarioId !== "") {
            $scenarios[$scenarioId] = array(
                "scenario_id" => $scenarioId,
                "category" => $category,
                "scenario_kind" => $scenarioKind,
                "expected_confirmed" => $expectedConfirmed,
                "expected_outcome" => $expectedOutcome,
                "expected_decision_tier" => $expectedTier,
                "expected_reason_codes_any" => $expectedReasonCodesAny,
                "endpoint" => $endpoint,
            );
        }
    }
}

$resultsPath = rtrim($runtimeDir, "/") . "/results.jsonl";
$decisionsPath = rtrim($runtimeDir, "/") . "/decisions.jsonl";
$deadLettersPath = rtrim($runtimeDir, "/") . "/dead_letters.jsonl";
if ($extensionAssertionsSummaryPath === "") {
    $extensionAssertionsSummaryPath = rtrim($runtimeDir, "/") . "/extension_assertions_summary.json";
}
if ($scenarioRequirementsSummaryPath === "") {
    $scenarioRequirementsSummaryPath = rtrim($runtimeDir, "/") . "/scenario_requirements_summary.json";
}
$resultLines = @file($resultsPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
$decisionLines = @file($decisionsPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
$deadLetterLines = @file($deadLettersPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
if (!is_array($resultLines)) {
    $errors[] = "missing or unreadable results file: " . $resultsPath;
    $resultLines = array();
}
if (!is_array($decisionLines)) {
    $errors[] = "missing or unreadable decisions file: " . $decisionsPath;
    $decisionLines = array();
}
if (!is_array($deadLetterLines)) {
    $deadLetterLines = array();
}

$extensionAssertions = array(
    "summary_path" => $extensionAssertionsSummaryPath,
    "present" => false,
    "parse_error" => null,
    "profile" => null,
    "strict" => null,
    "optional_assertions_total" => 0,
    "optional_assertions_executed" => 0,
    "optional_assertions_skipped" => 0,
    "skip_rate" => 0.0,
    "required_assertions_for_profile" => array(),
);

if ($extensionAssertionsSummaryPath !== "" && is_file($extensionAssertionsSummaryPath)) {
    $extensionAssertions["present"] = true;
    $rawExtensionSummary = @file_get_contents($extensionAssertionsSummaryPath);
    $decodedExtensionSummary = is_string($rawExtensionSummary) ? json_decode($rawExtensionSummary, true) : null;
    if (!is_array($decodedExtensionSummary)) {
        $extensionAssertions["parse_error"] = "invalid_json";
    } else {
        $extensionAssertions["profile"] = isset($decodedExtensionSummary["profile"])
            ? (string) $decodedExtensionSummary["profile"]
            : null;
        $extensionAssertions["strict"] = array_key_exists("strict", $decodedExtensionSummary)
            ? (bool) $decodedExtensionSummary["strict"]
            : null;
        $total = max(0, (int) ($decodedExtensionSummary["optional_assertions_total"] ?? 0));
        $executed = max(0, (int) ($decodedExtensionSummary["optional_assertions_executed"] ?? 0));
        $skipped = max(0, (int) ($decodedExtensionSummary["optional_assertions_skipped"] ?? 0));
        if ($total <= 0) {
            $total = $executed + $skipped;
        }
        $extensionAssertions["optional_assertions_total"] = $total;
        $extensionAssertions["optional_assertions_executed"] = $executed;
        $extensionAssertions["optional_assertions_skipped"] = $skipped;
        $extensionAssertions["skip_rate"] = $total > 0
            ? round((float) $skipped / (float) $total, 6)
            : round((float) ($decodedExtensionSummary["skip_rate"] ?? 0.0), 6);
        if (is_array($decodedExtensionSummary["required_assertions_for_profile"] ?? null)) {
            $required = array();
            foreach ($decodedExtensionSummary["required_assertions_for_profile"] as $entry) {
                if (is_scalar($entry) && trim((string) $entry) !== "") {
                    $required[] = trim((string) $entry);
                }
            }
            $extensionAssertions["required_assertions_for_profile"] = array_values(array_unique($required));
        }
    }
}

$scenarioRequirementsSummary = array(
    "summary_path" => $scenarioRequirementsSummaryPath,
    "present" => false,
    "parse_error" => null,
    "total_scenarios" => 0,
    "queued_scenarios" => 0,
    "skipped_scenarios_count" => 0,
    "skipped_scenarios" => array(),
);
$skippedByRequirements = array();

if ($scenarioRequirementsSummaryPath !== "" && is_file($scenarioRequirementsSummaryPath)) {
    $scenarioRequirementsSummary["present"] = true;
    $rawRequirementsSummary = @file_get_contents($scenarioRequirementsSummaryPath);
    $decodedRequirementsSummary = is_string($rawRequirementsSummary) ? json_decode($rawRequirementsSummary, true) : null;
    if (!is_array($decodedRequirementsSummary)) {
        $scenarioRequirementsSummary["parse_error"] = "invalid_json";
    } else {
        $scenarioRequirementsSummary["total_scenarios"] = max(0, (int) ($decodedRequirementsSummary["total_scenarios"] ?? 0));
        $scenarioRequirementsSummary["queued_scenarios"] = max(0, (int) ($decodedRequirementsSummary["queued_scenarios"] ?? 0));
        $scenarioRequirementsSummary["skipped_scenarios_count"] = max(0, (int) ($decodedRequirementsSummary["skipped_scenarios_count"] ?? 0));
        if (is_array($decodedRequirementsSummary["skipped_scenarios"] ?? null)) {
            foreach ($decodedRequirementsSummary["skipped_scenarios"] as $row) {
                if (!is_array($row)) {
                    continue;
                }

                $scenarioId = trim((string) ($row["scenario_id"] ?? ""));
                if ($scenarioId === "") {
                    continue;
                }

                $skipReasons = array();
                if (is_array($row["skip_reasons"] ?? null)) {
                    foreach ($row["skip_reasons"] as $skipReason) {
                        if (!is_scalar($skipReason)) {
                            continue;
                        }
                        $normalizedSkipReason = trim((string) $skipReason);
                        if ($normalizedSkipReason === "") {
                            continue;
                        }
                        $skipReasons[] = $normalizedSkipReason;
                    }
                }
                $skipReasons = array_values(array_unique($skipReasons));

                $normalizedRow = array(
                    "scenario_id" => $scenarioId,
                    "corpus_file" => trim((string) ($row["corpus_file"] ?? "")),
                    "skip_reasons" => $skipReasons,
                );
                $scenarioRequirementsSummary["skipped_scenarios"][] = $normalizedRow;
                $skippedByRequirements[$scenarioId] = $normalizedRow;
            }
        }
        if ($scenarioRequirementsSummary["skipped_scenarios_count"] === 0) {
            $scenarioRequirementsSummary["skipped_scenarios_count"] = count($scenarioRequirementsSummary["skipped_scenarios"]);
        }
    }
}

$resultsByCandidate = array();
$resultOutcomeDistribution = array();
$replayFailedCount = 0;
$totalResults = 0;
foreach ($resultLines as $line) {
    $row = json_decode($line, true);
    if (!is_array($row)) {
        continue;
    }

    $outcome = (string) ($row["outcome"] ?? "");
    if ($outcome !== "") {
        $resultOutcomeDistribution[$outcome] = (int) ($resultOutcomeDistribution[$outcome] ?? 0) + 1;
        $totalResults++;
        if ($outcome === "replay_failed") {
            $replayFailedCount++;
        }
    }

    $candidateId = (string) ($row["candidate_id"] ?? "");
    if ($candidateId === "") {
        continue;
    }
    $resultsByCandidate[$candidateId] = $row;
}
ksort($resultOutcomeDistribution);
$replayFailureRate = $totalResults > 0 ? $replayFailedCount / $totalResults : 0.0;

$decisionsByCandidate = array();
$tierDistribution = array();
$formulaVersionDistribution = array();
$reasonCodeDistribution = array();
$xssBrowserProbeStats = array(
    "xss_confirmed_decisions" => 0,
    "browser_reason_present_count" => 0,
    "execution_confirmed_count" => 0,
    "failure_count" => 0,
    "unconfigured_count" => 0,
);
$decisionCount = 0;
foreach ($decisionLines as $line) {
    $row = json_decode($line, true);
    if (!is_array($row)) {
        continue;
    }
    $decisionCount++;

    $candidateId = (string) ($row["candidate_id"] ?? "");
    if ($candidateId !== "") {
        $decisionsByCandidate[$candidateId] = $row;
    }

    $tier = (string) ($row["decision_tier"] ?? "");
    if ($tier !== "") {
        $tierDistribution[$tier] = (int) ($tierDistribution[$tier] ?? 0) + 1;
    }

    $formulaVersion = (string) (($row["score_breakdown"]["formula_version"] ?? "") ?: "missing");
    $formulaVersionDistribution[$formulaVersion] = (int) ($formulaVersionDistribution[$formulaVersion] ?? 0) + 1;

    if (is_array($row["reason_codes"] ?? null)) {
        foreach ($row["reason_codes"] as $reasonCode) {
            $normalizedReasonCode = trim((string) $reasonCode);
            if ($normalizedReasonCode === "") {
                continue;
            }
            $reasonCodeDistribution[$normalizedReasonCode] = (int) ($reasonCodeDistribution[$normalizedReasonCode] ?? 0) + 1;
        }
    }

    $category = is_array($row["metadata"] ?? null) ? (string) ($row["metadata"]["sink_category"] ?? "") : "";
    if ($category === "xss" && (string) ($row["decision_tier"] ?? "") === "confirmed") {
        $xssBrowserProbeStats["xss_confirmed_decisions"]++;
        $hasBrowserReason = false;
        $hasExecutionConfirmed = false;
        $hasUnconfigured = false;
        $hasFailure = false;
        $reasonCodes = is_array($row["reason_codes"] ?? null) ? $row["reason_codes"] : array();
        foreach ($reasonCodes as $rawReasonCode) {
            $reasonCode = trim((string) $rawReasonCode);
            if ($reasonCode === "") {
                continue;
            }
            if (str_starts_with($reasonCode, "VERIFIER_XSS_BROWSER_")) {
                $hasBrowserReason = true;
            }
            if ($reasonCode === "VERIFIER_XSS_BROWSER_EXECUTION_CONFIRMED") {
                $hasExecutionConfirmed = true;
            }
            if ($reasonCode === "VERIFIER_XSS_BROWSER_PROBE_UNCONFIGURED") {
                $hasUnconfigured = true;
            }
            if (in_array($reasonCode, array(
                "VERIFIER_XSS_BROWSER_PROBE_FAILED",
                "VERIFIER_XSS_BROWSER_EXECUTION_NOT_OBSERVED",
                "VERIFIER_XSS_BROWSER_REQUEST_PARSE_FAILED",
                "VERIFIER_XSS_BROWSER_METHOD_BLOCKED",
                "VERIFIER_XSS_BROWSER_TARGET_PARAM_MISSING",
            ), true)) {
                $hasFailure = true;
            }
        }

        if ($hasBrowserReason) {
            $xssBrowserProbeStats["browser_reason_present_count"]++;
        }
        if ($hasExecutionConfirmed) {
            $xssBrowserProbeStats["execution_confirmed_count"]++;
        }
        if ($hasUnconfigured) {
            $xssBrowserProbeStats["unconfigured_count"]++;
        }
        if ($hasFailure) {
            $xssBrowserProbeStats["failure_count"]++;
        }
    }
}
ksort($tierDistribution);
ksort($formulaVersionDistribution);
ksort($reasonCodeDistribution);

$deadLetterCount = 0;
$deadLetterReasonDistribution = array();
foreach ($deadLetterLines as $line) {
    $row = json_decode($line, true);
    if (!is_array($row)) {
        continue;
    }

    $deadLetterCount++;
    $reasonCode = trim((string) ($row["reason_code"] ?? ""));
    if ($reasonCode !== "") {
        $deadLetterReasonDistribution[$reasonCode] = (int) ($deadLetterReasonDistribution[$reasonCode] ?? 0) + 1;
    }
}
ksort($deadLetterReasonDistribution);
$deadLetterReasonCountForPrefix = static function (array $distribution, string $prefix): int {
    $count = 0;
    foreach ($distribution as $reasonCode => $reasonCount) {
        if (str_starts_with((string) $reasonCode, $prefix)) {
            $count += (int) $reasonCount;
        }
    }
    return $count;
};
$deadLetterReasonRate = static function (int $reasonCount, int $resultCount): float {
    if ($resultCount > 0) {
        return (float) $reasonCount / (float) $resultCount;
    }
    return $reasonCount > 0 ? 1.0 : 0.0;
};
$deadLetterRate = $totalResults > 0
    ? ((float) $deadLetterCount / (float) $totalResults)
    : ($deadLetterCount > 0 ? 1.0 : 0.0);
$deadLetterReasonBudgetViolations = array();
$deadLetterReasonBudgetObserved = array();
if ($deadLetterReasonBudgets !== array()) {
    foreach ($deadLetterReasonBudgets as $prefix => $maxCount) {
        $observedCount = $deadLetterReasonCountForPrefix($deadLetterReasonDistribution, (string) $prefix);

        $deadLetterReasonBudgetObserved[$prefix] = array(
            "max_count" => $maxCount,
            "observed_count" => $observedCount,
            "exceeded" => $observedCount > $maxCount,
        );
        if ($observedCount > $maxCount) {
            $deadLetterReasonBudgetViolations[] = array(
                "prefix" => $prefix,
                "max_count" => $maxCount,
                "observed_count" => $observedCount,
            );
        }
    }
    ksort($deadLetterReasonBudgetObserved);
}
$deadLetterReasonRateDriftObserved = array();
if ($driftDeadLetterReasonRateThresholds !== array()) {
    foreach ($driftDeadLetterReasonRateThresholds as $prefix => $threshold) {
        $observedCount = $deadLetterReasonCountForPrefix($deadLetterReasonDistribution, (string) $prefix);
        $deadLetterReasonRateDriftObserved[$prefix] = array(
            "threshold" => (float) $threshold,
            "observed_count" => $observedCount,
            "current_rate" => round($deadLetterReasonRate($observedCount, $totalResults), 6),
            "baseline_rate" => null,
            "delta" => null,
            "alert" => null,
        );
    }
    ksort($deadLetterReasonRateDriftObserved);
}

$xssConfirmedDecisionCount = (int) $xssBrowserProbeStats["xss_confirmed_decisions"];
$xssBrowserProbeStats["browser_reason_present_rate"] = $xssConfirmedDecisionCount > 0
    ? round((float) $xssBrowserProbeStats["browser_reason_present_count"] / (float) $xssConfirmedDecisionCount, 6)
    : 0.0;
$xssBrowserProbeStats["execution_confirmed_rate"] = $xssConfirmedDecisionCount > 0
    ? round((float) $xssBrowserProbeStats["execution_confirmed_count"] / (float) $xssConfirmedDecisionCount, 6)
    : 0.0;
$xssBrowserProbeStats["failure_rate"] = $xssConfirmedDecisionCount > 0
    ? round((float) $xssBrowserProbeStats["failure_count"] / (float) $xssConfirmedDecisionCount, 6)
    : 0.0;
$xssBrowserProbeStats["unconfigured_rate"] = $xssConfirmedDecisionCount > 0
    ? round((float) $xssBrowserProbeStats["unconfigured_count"] / (float) $xssConfirmedDecisionCount, 6)
    : 0.0;

$formulaVersionUnexpected = array();
$formulaVersionMatched = true;
if ($expectedFormulaVersion !== "") {
    foreach ($formulaVersionDistribution as $formulaVersion => $count) {
        if ($formulaVersion !== $expectedFormulaVersion) {
            $formulaVersionUnexpected[] = array(
                "formula_version" => $formulaVersion,
                "count" => $count,
            );
        }
    }
    $formulaVersionMatched = $formulaVersionUnexpected === array();
}

$tp = 0;
$fp = 0;
$fn = 0;
$tn = 0;
$unexpectedConfirmed = array();
$safeUnexpectedConfirmed = array();
$reasonCodeMismatches = array();
$scenarioEvaluations = array();
$evaluatedScenarioCount = 0;
$skippedByRequirementsCount = 0;

foreach ($scenarios as $scenarioId => $scenario) {
    $expectedTier = (string) $scenario["expected_decision_tier"];
    $expectedOutcome = (string) $scenario["expected_outcome"];
    $scenarioKind = (string) $scenario["scenario_kind"];
    $expectedConfirmed = (bool) $scenario["expected_confirmed"];
    $requirementsSkipRow = $skippedByRequirements[$scenarioId] ?? null;

    if (is_array($requirementsSkipRow)) {
        $skippedByRequirementsCount++;
        $scenarioEvaluations[] = array(
            "scenario_id" => $scenarioId,
            "category" => $scenario["category"],
            "scenario_kind" => $scenarioKind,
            "expected_confirmed" => $expectedConfirmed,
            "expected_outcome" => $expectedOutcome,
            "observed_outcome" => "skipped_by_requirements",
            "expected_decision_tier" => $expectedTier,
            "observed_decision_tier" => "skipped_by_requirements",
            "expected_reason_codes_any" => is_array($scenario["expected_reason_codes_any"] ?? null)
                ? $scenario["expected_reason_codes_any"]
                : array(),
            "observed_reason_codes" => array(),
            "reason_code_expectation_met" => null,
            "evaluation_status" => "skipped_by_requirements",
            "skip_reasons" => is_array($requirementsSkipRow["skip_reasons"] ?? null)
                ? $requirementsSkipRow["skip_reasons"]
                : array(),
            "corpus_file" => (string) ($requirementsSkipRow["corpus_file"] ?? ""),
        );
        continue;
    }

    $evaluatedScenarioCount++;

    $resultRow = $resultsByCandidate[$scenarioId] ?? null;
    $decisionRow = $decisionsByCandidate[$scenarioId] ?? null;

    $observedOutcome = is_array($resultRow) ? (string) ($resultRow["outcome"] ?? "missing") : "missing";
    $observedTier = is_array($decisionRow) ? (string) ($decisionRow["decision_tier"] ?? "missing") : "missing";
    $observedReasonCodes = is_array($decisionRow) && is_array($decisionRow["reason_codes"] ?? null)
        ? array_values(array_map(static fn ($value): string => (string) $value, $decisionRow["reason_codes"]))
        : array();

    $expectedPositive = $expectedConfirmed;
    $observedPositive = ($observedTier === "confirmed");

    if ($expectedPositive && $observedPositive) {
        $tp++;
    } elseif (!$expectedPositive && $observedPositive) {
        $fp++;
    } elseif ($expectedPositive && !$observedPositive) {
        $fn++;
    } else {
        $tn++;
    }

    if ($observedPositive && !$expectedPositive) {
        $unexpectedConfirmed[] = array(
            "scenario_id" => $scenarioId,
            "category" => $scenario["category"],
            "scenario_kind" => $scenarioKind,
            "observed_tier" => $observedTier,
            "expected_tier" => $expectedTier,
        );
    }
    if ($observedPositive && $scenarioKind === "safe") {
        $safeUnexpectedConfirmed[] = array(
            "scenario_id" => $scenarioId,
            "category" => $scenario["category"],
            "observed_tier" => $observedTier,
            "expected_confirmed" => false,
        );
    }

    $expectedReasonCodesAny = is_array($scenario["expected_reason_codes_any"] ?? null)
        ? $scenario["expected_reason_codes_any"]
        : array();
    $reasonCodeExpectationMet = true;
    if ($expectedReasonCodesAny !== array()) {
        $reasonCodeExpectationMet = count(array_intersect($expectedReasonCodesAny, $observedReasonCodes)) > 0;
        if (!$reasonCodeExpectationMet) {
            $reasonCodeMismatches[] = array(
                "scenario_id" => $scenarioId,
                "category" => $scenario["category"],
                "expected_reason_codes_any" => $expectedReasonCodesAny,
                "observed_reason_codes" => $observedReasonCodes,
            );
        }
    }

    $scenarioEvaluations[] = array(
        "scenario_id" => $scenarioId,
        "category" => $scenario["category"],
        "scenario_kind" => $scenarioKind,
        "expected_confirmed" => $expectedConfirmed,
        "expected_outcome" => $expectedOutcome,
        "observed_outcome" => $observedOutcome,
        "expected_decision_tier" => $expectedTier,
        "observed_decision_tier" => $observedTier,
        "expected_reason_codes_any" => $expectedReasonCodesAny,
        "observed_reason_codes" => $observedReasonCodes,
        "reason_code_expectation_met" => $reasonCodeExpectationMet,
        "evaluation_status" => "evaluated",
    );
}

$precision = ($tp + $fp) > 0 ? $tp / ($tp + $fp) : 0.0;
$recall = ($tp + $fn) > 0 ? $tp / ($tp + $fn) : 0.0;
$f1 = ($precision + $recall) > 0.0 ? (2.0 * $precision * $recall) / ($precision + $recall) : 0.0;

$normalizeDistribution = static function (array $distribution): array {
    $sum = array_sum($distribution);
    if (!is_numeric($sum) || (float) $sum <= 0.0) {
        return array();
    }

    $normalized = array();
    foreach ($distribution as $key => $count) {
        $normalized[(string) $key] = (float) $count / (float) $sum;
    }
    ksort($normalized);
    return $normalized;
};

$distributionL1Distance = static function (array $left, array $right): float {
    $keys = array_values(array_unique(array_merge(array_keys($left), array_keys($right))));
    $distance = 0.0;
    foreach ($keys as $key) {
        $leftValue = (float) ($left[$key] ?? 0.0);
        $rightValue = (float) ($right[$key] ?? 0.0);
        $distance += abs($leftValue - $rightValue);
    }
    return $distance;
};

$currentConfirmedRatio = $decisionCount > 0
    ? ((float) ($tierDistribution["confirmed"] ?? 0) / (float) $decisionCount)
    : 0.0;

$drift = array(
    "baseline_path" => $baselinePath === "" ? null : $baselinePath,
    "thresholds" => array(
        "confirmed_ratio_delta" => $driftConfirmedRatioDeltaThreshold,
        "replay_failure_rate_delta" => $driftReplayFailureRateDeltaThreshold,
        "reason_distribution_l1" => $driftReasonDistributionL1Threshold,
        "xss_browser_exec_confirmed_rate_drop" => $driftXssBrowserExecConfirmedRateDropThreshold,
        "xss_browser_failure_rate_delta" => $driftXssBrowserFailureRateDeltaThreshold,
        "xss_browser_unconfigured_rate_delta" => $driftXssBrowserUnconfiguredRateDeltaThreshold,
        "dead_letter_rate_delta" => $driftDeadLetterRateDeltaThreshold,
        "extension_assertion_skip_rate_delta" => $driftExtensionAssertionSkipRateDeltaThreshold,
        "dead_letter_reason_rate_delta" => $driftDeadLetterReasonRateThresholds,
    ),
    "alerts" => array(),
);

if ($baselinePath !== "") {
    if (!is_file($baselinePath)) {
        $errors[] = "baseline file does not exist: " . $baselinePath;
    } else {
        $baselinePayload = json_decode((string) @file_get_contents($baselinePath), true);
        if (!is_array($baselinePayload)) {
            $errors[] = "invalid baseline JSON: " . $baselinePath;
        } else {
            $baselineTierDistribution = is_array($baselinePayload["decision_tier_distribution"] ?? null)
                ? $baselinePayload["decision_tier_distribution"]
                : array();
            $baselineDecisionCount = (int) array_sum(array_map(static fn (mixed $value): int => (int) $value, $baselineTierDistribution));
            $baselineConfirmedRatio = $baselineDecisionCount > 0
                ? ((float) ($baselineTierDistribution["confirmed"] ?? 0) / (float) $baselineDecisionCount)
                : 0.0;

            $baselineReplayFailureRate = null;
            if (is_array($baselinePayload["replay"] ?? null) && array_key_exists("replay_failure_rate", $baselinePayload["replay"])) {
                $baselineReplayFailureRate = (float) $baselinePayload["replay"]["replay_failure_rate"];
            }
            if ($baselineReplayFailureRate === null) {
                $baselineReplayFailureRate = 0.0;
            }

            $currentReasonDistributionNormalized = $normalizeDistribution($reasonCodeDistribution);
            $baselineReasonDistributionRaw = is_array($baselinePayload["reason_code_distribution"] ?? null)
                ? $baselinePayload["reason_code_distribution"]
                : array();
            $baselineReasonDistributionNormalized = $normalizeDistribution($baselineReasonDistributionRaw);
            $reasonDistributionL1Distance = null;
            if ($currentReasonDistributionNormalized !== array() && $baselineReasonDistributionNormalized !== array()) {
                $reasonDistributionL1Distance = $distributionL1Distance(
                    $currentReasonDistributionNormalized,
                    $baselineReasonDistributionNormalized
                );
            }

            $baselineBrowserProbe = is_array($baselinePayload["browser_xss_probe"] ?? null)
                ? $baselinePayload["browser_xss_probe"]
                : array();
            $baselineXssBrowserExecutionConfirmedRate = array_key_exists("execution_confirmed_rate", $baselineBrowserProbe)
                ? (float) $baselineBrowserProbe["execution_confirmed_rate"]
                : null;
            $baselineXssBrowserFailureRate = array_key_exists("failure_rate", $baselineBrowserProbe)
                ? (float) $baselineBrowserProbe["failure_rate"]
                : null;
            $baselineXssBrowserUnconfiguredRate = array_key_exists("unconfigured_rate", $baselineBrowserProbe)
                ? (float) $baselineBrowserProbe["unconfigured_rate"]
                : null;
            $baselineDeadLetterRate = null;
            if (is_array($baselinePayload["queue"] ?? null) && array_key_exists("dead_letter_rate", $baselinePayload["queue"])) {
                $baselineDeadLetterRate = (float) $baselinePayload["queue"]["dead_letter_rate"];
            }
            if ($baselineDeadLetterRate === null) {
                $baselineDeadLetterRate = 0.0;
            }
            $baselineExtensionAssertionSkipRate = null;
            if (is_array($baselinePayload["extension_assertions"] ?? null)
                && array_key_exists("skip_rate", $baselinePayload["extension_assertions"])
            ) {
                $baselineExtensionAssertionSkipRate = (float) $baselinePayload["extension_assertions"]["skip_rate"];
            }
            if ($baselineExtensionAssertionSkipRate === null) {
                $baselineExtensionAssertionSkipRate = 0.0;
            }
            $baselineDeadLetterReasonDistribution = array();
            if (is_array($baselinePayload["queue"] ?? null) && is_array($baselinePayload["queue"]["dead_letter_reason_distribution"] ?? null)) {
                $baselineDeadLetterReasonDistribution = $baselinePayload["queue"]["dead_letter_reason_distribution"];
            }
            $baselineReplayTotalResults = null;
            if (is_array($baselinePayload["replay"] ?? null) && array_key_exists("total_results", $baselinePayload["replay"])) {
                $baselineReplayTotalResults = (int) $baselinePayload["replay"]["total_results"];
            }
            if ($baselineReplayTotalResults === null || $baselineReplayTotalResults < 0) {
                $baselineReplayTotalResults = 0;
            }

            $confirmedRatioDelta = $currentConfirmedRatio - $baselineConfirmedRatio;
            $replayFailureRateDelta = $replayFailureRate - $baselineReplayFailureRate;
            $deadLetterRateDelta = $deadLetterRate - $baselineDeadLetterRate;
            $extensionAssertionSkipRateDelta = (float) ($extensionAssertions["skip_rate"] ?? 0.0) - $baselineExtensionAssertionSkipRate;
            $confirmedRatioAlert = $confirmedRatioDelta > $driftConfirmedRatioDeltaThreshold;
            $replayFailureRateAlert = $replayFailureRateDelta > $driftReplayFailureRateDeltaThreshold;
            $deadLetterRateAlert = $deadLetterRateDelta > $driftDeadLetterRateDeltaThreshold;
            $extensionAssertionSkipRateAlert = $extensionAssertionSkipRateDelta > $driftExtensionAssertionSkipRateDeltaThreshold;
            $reasonDistributionAlert = $reasonDistributionL1Distance !== null
                ? ($reasonDistributionL1Distance > $driftReasonDistributionL1Threshold)
                : false;
            $currentXssBrowserExecutionConfirmedRate = (float) $xssBrowserProbeStats["execution_confirmed_rate"];
            $currentXssBrowserFailureRate = (float) $xssBrowserProbeStats["failure_rate"];
            $currentXssBrowserUnconfiguredRate = (float) $xssBrowserProbeStats["unconfigured_rate"];
            $xssBrowserExecDrop = $baselineXssBrowserExecutionConfirmedRate !== null
                ? ($baselineXssBrowserExecutionConfirmedRate - $currentXssBrowserExecutionConfirmedRate)
                : null;
            $xssBrowserFailureDelta = $baselineXssBrowserFailureRate !== null
                ? ($currentXssBrowserFailureRate - $baselineXssBrowserFailureRate)
                : null;
            $xssBrowserUnconfiguredDelta = $baselineXssBrowserUnconfiguredRate !== null
                ? ($currentXssBrowserUnconfiguredRate - $baselineXssBrowserUnconfiguredRate)
                : null;
            $xssBrowserExecDropAlert = $xssBrowserExecDrop !== null
                ? ($xssBrowserExecDrop > $driftXssBrowserExecConfirmedRateDropThreshold)
                : false;
            $xssBrowserFailureAlert = $xssBrowserFailureDelta !== null
                ? ($xssBrowserFailureDelta > $driftXssBrowserFailureRateDeltaThreshold)
                : false;
            $xssBrowserUnconfiguredAlert = $xssBrowserUnconfiguredDelta !== null
                ? ($xssBrowserUnconfiguredDelta > $driftXssBrowserUnconfiguredRateDeltaThreshold)
                : false;

            if ($confirmedRatioAlert) {
                $drift["alerts"][] = array(
                    "type" => "confirmed_ratio_spike",
                    "delta" => $confirmedRatioDelta,
                    "threshold" => $driftConfirmedRatioDeltaThreshold,
                );
            }
            if ($replayFailureRateAlert) {
                $drift["alerts"][] = array(
                    "type" => "replay_failure_rate_spike",
                    "delta" => $replayFailureRateDelta,
                    "threshold" => $driftReplayFailureRateDeltaThreshold,
                );
            }
            if ($deadLetterRateAlert) {
                $drift["alerts"][] = array(
                    "type" => "dead_letter_rate_spike",
                    "delta" => $deadLetterRateDelta,
                    "threshold" => $driftDeadLetterRateDeltaThreshold,
                );
            }
            if ($extensionAssertionSkipRateAlert) {
                $drift["alerts"][] = array(
                    "type" => "extension_assertion_skip_rate_spike",
                    "delta" => $extensionAssertionSkipRateDelta,
                    "threshold" => $driftExtensionAssertionSkipRateDeltaThreshold,
                );
            }
            if ($driftDeadLetterReasonRateThresholds !== array()) {
                foreach ($driftDeadLetterReasonRateThresholds as $prefix => $threshold) {
                    $currentPrefixCount = $deadLetterReasonCountForPrefix($deadLetterReasonDistribution, (string) $prefix);
                    $baselinePrefixCount = $deadLetterReasonCountForPrefix($baselineDeadLetterReasonDistribution, (string) $prefix);
                    $currentRate = $deadLetterReasonRate($currentPrefixCount, $totalResults);
                    $baselineRate = $deadLetterReasonRate($baselinePrefixCount, $baselineReplayTotalResults);
                    $delta = $currentRate - $baselineRate;
                    $alert = $delta > (float) $threshold;

                    $deadLetterReasonRateDriftObserved[$prefix] = array(
                        "threshold" => round((float) $threshold, 6),
                        "observed_count" => $currentPrefixCount,
                        "baseline_count" => $baselinePrefixCount,
                        "current_rate" => round($currentRate, 6),
                        "baseline_rate" => round($baselineRate, 6),
                        "delta" => round($delta, 6),
                        "alert" => $alert,
                    );

                    if ($alert) {
                        $drift["alerts"][] = array(
                            "type" => "dead_letter_reason_rate_spike",
                            "prefix" => $prefix,
                            "delta" => $delta,
                            "threshold" => (float) $threshold,
                        );
                    }
                }
            }
            if ($reasonDistributionAlert) {
                $drift["alerts"][] = array(
                    "type" => "reason_code_distribution_shift",
                    "distance" => $reasonDistributionL1Distance,
                    "threshold" => $driftReasonDistributionL1Threshold,
                );
            }
            if ($xssBrowserExecDropAlert) {
                $drift["alerts"][] = array(
                    "type" => "xss_browser_exec_confirmed_rate_drop",
                    "delta" => $xssBrowserExecDrop,
                    "threshold" => $driftXssBrowserExecConfirmedRateDropThreshold,
                );
            }
            if ($xssBrowserFailureAlert) {
                $drift["alerts"][] = array(
                    "type" => "xss_browser_failure_rate_spike",
                    "delta" => $xssBrowserFailureDelta,
                    "threshold" => $driftXssBrowserFailureRateDeltaThreshold,
                );
            }
            if ($xssBrowserUnconfiguredAlert) {
                $drift["alerts"][] = array(
                    "type" => "xss_browser_unconfigured_rate_spike",
                    "delta" => $xssBrowserUnconfiguredDelta,
                    "threshold" => $driftXssBrowserUnconfiguredRateDeltaThreshold,
                );
            }

            $drift["confirmed_ratio"] = array(
                "baseline" => round($baselineConfirmedRatio, 6),
                "current" => round($currentConfirmedRatio, 6),
                "delta" => round($confirmedRatioDelta, 6),
                "threshold" => round($driftConfirmedRatioDeltaThreshold, 6),
                "alert" => $confirmedRatioAlert,
            );
            $drift["replay_failure_rate"] = array(
                "baseline" => round($baselineReplayFailureRate, 6),
                "current" => round($replayFailureRate, 6),
                "delta" => round($replayFailureRateDelta, 6),
                "threshold" => round($driftReplayFailureRateDeltaThreshold, 6),
                "alert" => $replayFailureRateAlert,
            );
            $drift["dead_letter_rate"] = array(
                "baseline" => round($baselineDeadLetterRate, 6),
                "current" => round($deadLetterRate, 6),
                "delta" => round($deadLetterRateDelta, 6),
                "threshold" => round($driftDeadLetterRateDeltaThreshold, 6),
                "alert" => $deadLetterRateAlert,
            );
            $drift["extension_assertion_skip_rate"] = array(
                "baseline" => round($baselineExtensionAssertionSkipRate, 6),
                "current" => round((float) ($extensionAssertions["skip_rate"] ?? 0.0), 6),
                "delta" => round($extensionAssertionSkipRateDelta, 6),
                "threshold" => round($driftExtensionAssertionSkipRateDeltaThreshold, 6),
                "alert" => $extensionAssertionSkipRateAlert,
                "summary_present" => (bool) ($extensionAssertions["present"] ?? false),
            );
            if ($driftDeadLetterReasonRateThresholds !== array()) {
                $drift["dead_letter_reason_rate_by_prefix"] = $deadLetterReasonRateDriftObserved;
            }
            $drift["reason_distribution_l1"] = array(
                "baseline_available" => $baselineReasonDistributionNormalized !== array(),
                "current_available" => $currentReasonDistributionNormalized !== array(),
                "value" => $reasonDistributionL1Distance === null ? null : round($reasonDistributionL1Distance, 6),
                "threshold" => round($driftReasonDistributionL1Threshold, 6),
                "alert" => $reasonDistributionAlert,
            );
            $drift["xss_browser_exec_confirmed_rate"] = array(
                "baseline_available" => $baselineXssBrowserExecutionConfirmedRate !== null,
                "baseline" => $baselineXssBrowserExecutionConfirmedRate === null ? null : round($baselineXssBrowserExecutionConfirmedRate, 6),
                "current" => round($currentXssBrowserExecutionConfirmedRate, 6),
                "drop_delta" => $xssBrowserExecDrop === null ? null : round($xssBrowserExecDrop, 6),
                "threshold" => round($driftXssBrowserExecConfirmedRateDropThreshold, 6),
                "alert" => $xssBrowserExecDropAlert,
            );
            $drift["xss_browser_failure_rate"] = array(
                "baseline_available" => $baselineXssBrowserFailureRate !== null,
                "baseline" => $baselineXssBrowserFailureRate === null ? null : round($baselineXssBrowserFailureRate, 6),
                "current" => round($currentXssBrowserFailureRate, 6),
                "delta" => $xssBrowserFailureDelta === null ? null : round($xssBrowserFailureDelta, 6),
                "threshold" => round($driftXssBrowserFailureRateDeltaThreshold, 6),
                "alert" => $xssBrowserFailureAlert,
            );
            $drift["xss_browser_unconfigured_rate"] = array(
                "baseline_available" => $baselineXssBrowserUnconfiguredRate !== null,
                "baseline" => $baselineXssBrowserUnconfiguredRate === null ? null : round($baselineXssBrowserUnconfiguredRate, 6),
                "current" => round($currentXssBrowserUnconfiguredRate, 6),
                "delta" => $xssBrowserUnconfiguredDelta === null ? null : round($xssBrowserUnconfiguredDelta, 6),
                "threshold" => round($driftXssBrowserUnconfiguredRateDeltaThreshold, 6),
                "alert" => $xssBrowserUnconfiguredAlert,
            );
        }
    }
}

$metrics = array(
    "generated_at" => gmdate("c"),
    "runtime_dir" => $runtimeDir,
    "corpus_dir" => $corpusDir,
    "validation_errors" => $errors,
    "scenario_count" => count($scenarios),
    "scenario_count_total" => count($scenarios),
    "scenario_count_evaluated" => $evaluatedScenarioCount,
    "scenario_count_skipped_by_requirements" => $skippedByRequirementsCount,
    "scenario_requirements" => $scenarioRequirementsSummary,
    "counts" => array(
        "tp" => $tp,
        "fp" => $fp,
        "fn" => $fn,
        "tn" => $tn,
    ),
    "metrics" => array(
        "precision" => round($precision, 6),
        "recall" => round($recall, 6),
        "f1" => round($f1, 6),
    ),
    "replay" => array(
        "total_results" => $totalResults,
        "replay_failed_count" => $replayFailedCount,
        "replay_failure_rate" => round($replayFailureRate, 6),
    ),
    "queue" => array(
        "dead_letter_count" => $deadLetterCount,
        "dead_letter_rate" => round($deadLetterRate, 6),
        "dead_letter_reason_distribution" => $deadLetterReasonDistribution,
        "dead_letter_reason_budget_observed" => $deadLetterReasonBudgetObserved,
        "dead_letter_reason_budget_violations" => $deadLetterReasonBudgetViolations,
        "dead_letter_reason_rate_drift_observed" => $deadLetterReasonRateDriftObserved,
    ),
    "result_outcome_distribution" => $resultOutcomeDistribution,
    "decision_tier_distribution" => $tierDistribution,
    "formula_version_distribution" => $formulaVersionDistribution,
    "formula_version_check" => array(
        "expected_formula_version" => $expectedFormulaVersion === "" ? null : $expectedFormulaVersion,
        "matched" => $expectedFormulaVersion === "" ? null : $formulaVersionMatched,
        "unexpected" => $formulaVersionUnexpected,
    ),
    "browser_xss_probe" => $xssBrowserProbeStats,
    "extension_assertions" => $extensionAssertions,
    "reason_code_distribution" => $reasonCodeDistribution,
    "drift" => $drift,
    "unexpected_confirmed" => $unexpectedConfirmed,
    "safe_unexpected_confirmed" => $safeUnexpectedConfirmed,
    "reason_code_mismatches" => $reasonCodeMismatches,
    "scenarios" => $scenarioEvaluations,
);

$encoded = json_encode($metrics, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
if (!is_string($encoded)) {
    fwrite(STDERR, "failed to encode metrics payload" . PHP_EOL);
    exit(1);
}
file_put_contents($outputPath, $encoded . PHP_EOL);

echo "[metrics] scenarios(total=" . count($scenarios) . ", evaluated=" . $evaluatedScenarioCount . ", skipped_by_requirements=" . $skippedByRequirementsCount . ") tp={$tp} fp={$fp} fn={$fn} tn={$tn}" . PHP_EOL;
echo "[metrics] precision=" . sprintf("%.4f", $precision) . " recall=" . sprintf("%.4f", $recall) . " f1=" . sprintf("%.4f", $f1) . PHP_EOL;
echo "[metrics] replay_failure_rate=" . sprintf("%.4f", $replayFailureRate) . PHP_EOL;
echo "[metrics] dead_letters=" . $deadLetterCount . " dead_letter_rate=" . sprintf("%.4f", $deadLetterRate) . PHP_EOL;
echo "[metrics] extension_assertions=" . json_encode($extensionAssertions, JSON_UNESCAPED_SLASHES) . PHP_EOL;
if ($deadLetterReasonBudgets !== array()) {
    echo "[metrics] dead_letter_reason_budgets=" . json_encode($deadLetterReasonBudgetObserved, JSON_UNESCAPED_SLASHES) . PHP_EOL;
}
if ($driftDeadLetterReasonRateThresholds !== array()) {
    echo "[metrics] dead_letter_reason_rate_drift=" . json_encode($deadLetterReasonRateDriftObserved, JSON_UNESCAPED_SLASHES) . PHP_EOL;
}
echo "[metrics] decisions_by_tier=" . json_encode($tierDistribution, JSON_UNESCAPED_SLASHES) . PHP_EOL;
echo "[metrics] formula_versions=" . json_encode($formulaVersionDistribution, JSON_UNESCAPED_SLASHES) . PHP_EOL;
echo "[metrics] xss_browser_probe=" . json_encode($xssBrowserProbeStats, JSON_UNESCAPED_SLASHES) . PHP_EOL;
if ($baselinePath !== "") {
    echo "[metrics] drift_alerts=" . count($drift["alerts"]) . " baseline=" . $baselinePath . PHP_EOL;
}
echo "[metrics] output=" . $outputPath . PHP_EOL;

if ($errors !== array()) {
    fwrite(STDERR, "[metrics] validation failed:" . PHP_EOL);
    foreach ($errors as $error) {
        fwrite(STDERR, "  - " . $error . PHP_EOL);
    }
    exit(1);
}

if ($failOnUnexpectedConfirmed && $unexpectedConfirmed !== array()) {
    fwrite(STDERR, "[metrics] unexpected confirmed decisions detected:" . PHP_EOL);
    foreach ($unexpectedConfirmed as $row) {
        fwrite(
            STDERR,
            sprintf(
                "  - %s (%s): observed=%s expected=%s%s",
                $row["scenario_id"],
                $row["category"],
                $row["observed_tier"],
                $row["expected_tier"],
                PHP_EOL
            )
        );
    }
    exit(1);
}

if ($failOnUnexpectedConfirmed && $safeUnexpectedConfirmed !== array()) {
    fwrite(STDERR, "[metrics] safe-scenario confirmed decisions detected:" . PHP_EOL);
    foreach ($safeUnexpectedConfirmed as $row) {
        fwrite(
            STDERR,
            sprintf(
                "  - %s (%s): observed=%s expected_confirmed=false%s",
                $row["scenario_id"],
                $row["category"],
                $row["observed_tier"],
                PHP_EOL
            )
        );
    }
    exit(1);
}

if ($failOnFormulaVersionDrift && $expectedFormulaVersion !== "" && !$formulaVersionMatched) {
    fwrite(STDERR, "[metrics] formula version drift detected (expected " . $expectedFormulaVersion . "):" . PHP_EOL);
    foreach ($formulaVersionUnexpected as $row) {
        fwrite(
            STDERR,
            sprintf(
                "  - formula_version=%s count=%d%s",
                $row["formula_version"],
                (int) $row["count"],
                PHP_EOL
            )
        );
    }
    exit(1);
}

if ($failOnDrift && $drift["alerts"] !== array()) {
    fwrite(STDERR, "[metrics] drift alerts detected:" . PHP_EOL);
    foreach ($drift["alerts"] as $alert) {
        fwrite(STDERR, "  - " . json_encode($alert, JSON_UNESCAPED_SLASHES) . PHP_EOL);
    }
    exit(1);
}

if ($deadLetterReasonBudgetViolations !== array()) {
    fwrite(STDERR, "[metrics] dead-letter reason budget violations detected:" . PHP_EOL);
    foreach ($deadLetterReasonBudgetViolations as $violation) {
        fwrite(
            STDERR,
            sprintf(
                "  - prefix=%s observed=%d max=%d%s",
                $violation["prefix"],
                (int) $violation["observed_count"],
                (int) $violation["max_count"],
                PHP_EOL
            )
        );
    }
    exit(1);
}
' "${RUNTIME_DIR}" "${CORPUS_DIR}" "${OUTPUT_PATH}" "${FAIL_ON_UNEXPECTED_CONFIRMED}" "${EXPECTED_FORMULA_VERSION}" "${FAIL_ON_FORMULA_VERSION_DRIFT}" "${BASELINE_PATH}" "${FAIL_ON_DRIFT}" "${DRIFT_CONFIRMED_RATIO_DELTA_THRESHOLD}" "${DRIFT_REPLAY_FAILURE_RATE_DELTA_THRESHOLD}" "${DRIFT_REASON_DISTRIBUTION_L1_THRESHOLD}" "${DRIFT_XSS_BROWSER_EXEC_CONFIRMED_RATE_DROP_THRESHOLD}" "${DRIFT_XSS_BROWSER_FAILURE_RATE_DELTA_THRESHOLD}" "${DRIFT_XSS_BROWSER_UNCONFIGURED_RATE_DELTA_THRESHOLD}" "${DRIFT_DEAD_LETTER_RATE_DELTA_THRESHOLD}" "${DRIFT_EXTENSION_ASSERTION_SKIP_RATE_DELTA_THRESHOLD}" "${EXTENSION_ASSERTIONS_SUMMARY_PATH}" "${SCENARIO_REQUIREMENTS_SUMMARY_PATH}" "${DEAD_LETTER_REASON_MAX_COUNTS_CSV}" "${DRIFT_DEAD_LETTER_REASON_RATE_THRESHOLDS_CSV}"
