#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * Validate false-positive suite metrics for challenge/matrix runs.
 *
 * Usage:
 *   php scripts/validate_false_positive_suite_metrics.php --mode challenge --metrics /path/metrics.json
 *   php scripts/validate_false_positive_suite_metrics.php --mode matrix --metrics /path/metrics.json --corpus-dir /path/corpus
 */

$mode = '';
$metricsPath = '';
$corpusDir = '';

for ($i = 1; $i < $argc; $i++) {
    $arg = $argv[$i];
    if ($arg === '--mode' && isset($argv[$i + 1])) {
        $mode = (string) $argv[++$i];
        continue;
    }
    if ($arg === '--metrics' && isset($argv[$i + 1])) {
        $metricsPath = (string) $argv[++$i];
        continue;
    }
    if ($arg === '--corpus-dir' && isset($argv[$i + 1])) {
        $corpusDir = (string) $argv[++$i];
        continue;
    }
}

if ($mode !== 'challenge' && $mode !== 'matrix') {
    fwrite(STDERR, "[fp-validate] invalid --mode, expected challenge|matrix" . PHP_EOL);
    exit(1);
}
if ($metricsPath === '') {
    fwrite(STDERR, "[fp-validate] missing required --metrics argument" . PHP_EOL);
    exit(1);
}
if ($mode === 'matrix' && $corpusDir === '') {
    fwrite(STDERR, "[fp-validate] missing required --corpus-dir for matrix mode" . PHP_EOL);
    exit(1);
}

$prefix = $mode === 'challenge' ? '[fp-challenge]' : '[fp-matrix]';

$metricsRaw = @file_get_contents($metricsPath);
if (!is_string($metricsRaw) || trim($metricsRaw) === '') {
    fwrite(STDERR, $prefix . " metrics payload missing: " . $metricsPath . PHP_EOL);
    exit(1);
}

$metrics = json_decode($metricsRaw, true);
if (!is_array($metrics)) {
    fwrite(STDERR, $prefix . " metrics payload is invalid JSON: " . $metricsPath . PHP_EOL);
    exit(1);
}

$errors = array();
validateCommon($metrics, $errors);

if ($mode === 'challenge') {
    validateChallenge($metrics, $errors);
} else {
    validateMatrix($metrics, $corpusDir, $errors);
}

if ($errors !== array()) {
    fwrite(STDERR, $prefix . " validation failed:" . PHP_EOL);
    foreach ($errors as $error) {
        fwrite(STDERR, '  - ' . $error . PHP_EOL);
    }
    exit(1);
}

fwrite(STDOUT, $prefix . " validation passed" . PHP_EOL);

/**
 * @param array<string, mixed> $metrics
 * @param array<int, string> $errors
 */
function validateCommon(array $metrics, array &$errors): void
{
    $scenarioCount = (int) ($metrics['scenario_count'] ?? 0);
    $evaluatedScenarioCount = (int) ($metrics['scenario_count_evaluated'] ?? $scenarioCount);
    $counts = is_array($metrics['counts'] ?? null) ? $metrics['counts'] : array();
    $fp = (int) ($counts['fp'] ?? 0);
    $fn = (int) ($counts['fn'] ?? 0);
    $reasonMismatches = is_array($metrics['reason_code_mismatches'] ?? null) ? $metrics['reason_code_mismatches'] : array();
    $unexpectedConfirmed = is_array($metrics['unexpected_confirmed'] ?? null) ? $metrics['unexpected_confirmed'] : array();
    $safeUnexpectedConfirmed = is_array($metrics['safe_unexpected_confirmed'] ?? null) ? $metrics['safe_unexpected_confirmed'] : array();

    if ($scenarioCount <= 0) {
        $errors[] = 'scenario_count must be > 0';
    }
    if ($evaluatedScenarioCount <= 0) {
        $errors[] = 'scenario_count_evaluated must be > 0';
    }
    if ($fp !== 0) {
        $errors[] = 'expected zero false positives; observed fp=' . $fp;
    }
    if ($fn !== 0) {
        $errors[] = 'expected zero false negatives; observed fn=' . $fn;
    }
    if ($reasonMismatches !== array()) {
        $errors[] = 'reason_code_mismatches present: ' . count($reasonMismatches);
    }
    if ($unexpectedConfirmed !== array()) {
        $errors[] = 'unexpected_confirmed present: ' . count($unexpectedConfirmed);
    }
    if ($safeUnexpectedConfirmed !== array()) {
        $errors[] = 'safe_unexpected_confirmed present: ' . count($safeUnexpectedConfirmed);
    }
}

/**
 * @param array<string, mixed> $metrics
 * @param array<int, string> $errors
 */
function validateChallenge(array $metrics, array &$errors): void
{
    $scenarioRows = is_array($metrics['scenarios'] ?? null) ? $metrics['scenarios'] : array();
    $safeCountByCategory = array();
    $vulnCountByCategory = array();
    foreach ($scenarioRows as $row) {
        if (!is_array($row)) {
            continue;
        }
        $status = (string) ($row['evaluation_status'] ?? 'evaluated');
        if ($status === 'skipped_by_requirements') {
            continue;
        }

        $category = (string) ($row['category'] ?? '');
        $kind = (string) ($row['scenario_kind'] ?? '');
        if ($category === '') {
            continue;
        }

        if ($kind === 'safe') {
            $safeCountByCategory[$category] = (int) ($safeCountByCategory[$category] ?? 0) + 1;
        } elseif ($kind === 'vulnerable') {
            $vulnCountByCategory[$category] = (int) ($vulnCountByCategory[$category] ?? 0) + 1;
        }
    }

    foreach (array('rce', 'ssrf', 'sqli', 'file', 'xss', 'idor') as $category) {
        $safeCount = (int) ($safeCountByCategory[$category] ?? 0);
        $vulnCount = (int) ($vulnCountByCategory[$category] ?? 0);
        if ($safeCount < 2) {
            $errors[] = 'insufficient safe scenario coverage for category ' . $category . ': expected >=2, observed ' . $safeCount;
        }
        if ($vulnCount < 2) {
            $errors[] = 'insufficient vulnerable scenario coverage for category ' . $category . ': expected >=2, observed ' . $vulnCount;
        }
    }
}

/**
 * @param array<string, mixed> $metrics
 * @param array<int, string> $errors
 */
function validateMatrix(array $metrics, string $corpusDir, array &$errors): void
{
    $corpusFiles = glob(rtrim($corpusDir, '/') . '/*.json');
    if (!is_array($corpusFiles) || $corpusFiles === array()) {
        $errors[] = 'generated corpus is empty';
        $corpusFiles = array();
    }

    $expectedScenarioCount = count($corpusFiles);
    $observedScenarioCount = (int) ($metrics['scenario_count'] ?? 0);
    if ($observedScenarioCount !== $expectedScenarioCount) {
        $errors[] = 'scenario_count mismatch expected=' . $expectedScenarioCount . ' observed=' . $observedScenarioCount;
    }
    if ($expectedScenarioCount < 60) {
        $errors[] = 'generated corpus unexpectedly small: ' . $expectedScenarioCount;
    }

    $scenarioRows = is_array($metrics['scenarios'] ?? null) ? $metrics['scenarios'] : array();
    foreach ($scenarioRows as $row) {
        if (!is_array($row)) {
            continue;
        }
        $status = (string) ($row['evaluation_status'] ?? 'evaluated');
        if ($status === 'skipped_by_requirements') {
            continue;
        }
        $scenarioId = (string) ($row['scenario_id'] ?? '');
        $expectedOutcome = (string) ($row['expected_outcome'] ?? '');
        $observedOutcome = (string) ($row['observed_outcome'] ?? '');
        $expectedTier = (string) ($row['expected_decision_tier'] ?? '');
        $observedTier = (string) ($row['observed_decision_tier'] ?? '');

        if ($expectedOutcome !== $observedOutcome) {
            $errors[] = 'outcome drift for ' . $scenarioId . ': expected=' . $expectedOutcome . ' observed=' . $observedOutcome;
        }
        if ($expectedTier !== $observedTier) {
            $errors[] = 'decision tier drift for ' . $scenarioId . ': expected=' . $expectedTier . ' observed=' . $observedTier;
        }
    }

    $coverage = array();
    foreach ($corpusFiles as $file) {
        $row = json_decode((string) @file_get_contents($file), true);
        if (!is_array($row)) {
            $errors[] = 'invalid corpus file: ' . $file;
            continue;
        }

        $category = (string) ($row['category'] ?? '');
        $kind = (string) ($row['scenario_kind'] ?? '');
        $shape = (string) ($row['request_shape'] ?? '');
        if ($category === '' || $kind === '' || $shape === '') {
            $errors[] = 'missing category/scenario_kind/request_shape in ' . $file;
            continue;
        }
        $coverage[$category][$kind][$shape] = (int) ($coverage[$category][$kind][$shape] ?? 0) + 1;
    }

    $requiredCategories = array('rce', 'ssrf', 'sqli', 'file', 'xss', 'idor');
    $requiredKinds = array('safe', 'vulnerable');
    foreach ($requiredCategories as $category) {
        foreach ($requiredKinds as $kind) {
            foreach (array('query_get', 'query_post') as $shape) {
                $count = (int) ($coverage[$category][$kind][$shape] ?? 0);
                if ($count < 1) {
                    $errors[] = 'missing coverage for ' . $category . '/' . $kind . '/' . $shape;
                }
            }
            if ($category !== 'idor') {
                $count = (int) ($coverage[$category][$kind]['body_post'] ?? 0);
                if ($count < 1) {
                    $errors[] = 'missing coverage for ' . $category . '/' . $kind . '/body_post';
                }
            }
        }
    }
}
