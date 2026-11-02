<?php

declare(strict_types=1);

use PhpTaintTrace\Verification\Model\VerificationJob;
use PhpTaintTrace\Verification\Verifier\JsonlVerificationQueue;

$rootDir = dirname(__DIR__);
$autoloadPath = $rootDir . '/vendor/autoload.php';
if (!is_file($autoloadPath)) {
    fwrite(STDERR, "[php_taint_trace] Missing Composer autoload at {$autoloadPath}" . PHP_EOL);
    exit(1);
}

require $autoloadPath;

/**
 * @param string[] $argv
 * @return array{
 *   runtime_dir: string,
 *   reason_codes: array<int, string>,
 *   job_ids: array<int, string>,
 *   max: int,
 *   requeue_tag: string,
 *   dry_run: bool,
 *   summary_only: bool,
 *   include_requeued_jobs: bool
 * }
 */
function parseOptions(array $argv): array
{
    $options = array(
        'runtime_dir' => '.php_taint_trace_runtime/verifier',
        'reason_codes' => array(),
        'job_ids' => array(),
        'max' => 0,
        'requeue_tag' => 'dead_letter_requeue_v1',
        'dry_run' => false,
        'summary_only' => false,
        'include_requeued_jobs' => false,
    );

    $count = count($argv);
    for ($i = 1; $i < $count; $i++) {
        $arg = $argv[$i];
        switch ($arg) {
            case '--runtime-dir':
                $i++;
                $options['runtime_dir'] = (string) ($argv[$i] ?? '');
                break;
            case '--reason-code':
                $i++;
                $value = trim((string) ($argv[$i] ?? ''));
                if ($value !== '') {
                    $options['reason_codes'][] = $value;
                }
                break;
            case '--job-id':
                $i++;
                $value = trim((string) ($argv[$i] ?? ''));
                if ($value !== '') {
                    $options['job_ids'][] = $value;
                }
                break;
            case '--max':
                $i++;
                $value = (string) ($argv[$i] ?? '0');
                if (!preg_match('/^\d+$/', $value)) {
                    throw new RuntimeException('Invalid --max value, expected non-negative integer.');
                }
                $options['max'] = (int) $value;
                break;
            case '--requeue-tag':
                $i++;
                $value = trim((string) ($argv[$i] ?? ''));
                if ($value === '') {
                    throw new RuntimeException('Invalid --requeue-tag value, expected non-empty string.');
                }
                $options['requeue_tag'] = $value;
                break;
            case '--dry-run':
                $options['dry_run'] = true;
                break;
            case '--summary-only':
                $options['summary_only'] = true;
                break;
            case '--include-requeued-jobs':
                $options['include_requeued_jobs'] = true;
                break;
            case '-h':
            case '--help':
                fwrite(STDOUT, <<<USAGE
Usage: php scripts/requeue_verifier_dead_letters.php [options]

Options:
  --runtime-dir PATH          Verifier runtime directory (default: .php_taint_trace_runtime/verifier)
  --reason-code CODE          Filter to dead letters matching reason code (repeatable)
  --job-id ID                 Filter to dead letter job id (repeatable)
  --max N                     Maximum selected rows to process (0 means unlimited)
  --requeue-tag TAG           Stable tag used in replay_profile/job_id derivation
  --dry-run                   Preview requeue actions without writing jobs.jsonl
  --summary-only              Print dead-letter summary only
  --include-requeued-jobs     Include dead letters originating from prior requeue jobs
  -h, --help                  Show this help

Examples:
  php scripts/requeue_verifier_dead_letters.php --summary-only
  php scripts/requeue_verifier_dead_letters.php --reason-code VERIFIER_EXCEPTION_RETRY_EXHAUSTED --max 10 --dry-run
  php scripts/requeue_verifier_dead_letters.php --reason-code VERIFIER_EXCEPTION_RETRY_EXHAUSTED --requeue-tag manual_retry_001

USAGE);
                exit(0);
            default:
                throw new RuntimeException('Unknown argument: ' . $arg);
        }
    }

    $options['runtime_dir'] = trim((string) $options['runtime_dir']);
    if ($options['runtime_dir'] === '') {
        throw new RuntimeException('Invalid runtime directory (empty).');
    }

    $options['reason_codes'] = array_values(array_unique($options['reason_codes']));
    $options['job_ids'] = array_values(array_unique($options['job_ids']));

    return $options;
}

/**
 * @return array<int, array<string, mixed>>
 */
function readJsonLines(string $path): array
{
    $lines = @file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (!is_array($lines)) {
        return array();
    }

    $rows = array();
    foreach ($lines as $line) {
        $decoded = json_decode($line, true);
        if (!is_array($decoded)) {
            continue;
        }
        $rows[] = $decoded;
    }

    return $rows;
}

/**
 * @param array<string, mixed> $payload
 */
function appendJsonLine(string $path, array $payload): void
{
    $encoded = json_encode($payload, JSON_UNESCAPED_SLASHES);
    if (!is_string($encoded)) {
        throw new RuntimeException('Failed to encode JSONL payload.');
    }
    file_put_contents($path, $encoded . PHP_EOL, FILE_APPEND | LOCK_EX);
}

/**
 * @param array<string, mixed> $deadLetterRow
 */
function isRequeueOriginDeadLetter(array $deadLetterRow): bool
{
    $jobPayload = is_array($deadLetterRow['job'] ?? null)
        ? $deadLetterRow['job']
        : array();
    $metadata = is_array($jobPayload['metadata'] ?? null)
        ? $jobPayload['metadata']
        : array();

    return (string) ($metadata['requeue_source_job_id'] ?? '') !== '';
}

/**
 * @param array<string, mixed> $deadLetterRow
 */
function matchesFilters(array $deadLetterRow, array $options): bool
{
    if ($options['reason_codes'] !== array()) {
        $reasonCode = (string) ($deadLetterRow['reason_code'] ?? '');
        if (!in_array($reasonCode, $options['reason_codes'], true)) {
            return false;
        }
    }

    if ($options['job_ids'] !== array()) {
        $jobId = (string) ($deadLetterRow['job_id'] ?? '');
        if (!in_array($jobId, $options['job_ids'], true)) {
            return false;
        }
    }

    if (!$options['include_requeued_jobs'] && isRequeueOriginDeadLetter($deadLetterRow)) {
        return false;
    }

    return true;
}

try {
    $options = parseOptions($argv);
    $queue = new JsonlVerificationQueue($options['runtime_dir']);
    $deadLetterRows = readJsonLines($queue->deadLettersPath());
    $jobsPath = rtrim($options['runtime_dir'], '/') . '/jobs.jsonl';
    $requeuesPath = rtrim($options['runtime_dir'], '/') . '/requeues.jsonl';

    $reasonDistribution = array();
    foreach ($deadLetterRows as $row) {
        $reasonCode = trim((string) ($row['reason_code'] ?? ''));
        if ($reasonCode === '') {
            $reasonCode = 'UNKNOWN';
        }
        $reasonDistribution[$reasonCode] = (int) ($reasonDistribution[$reasonCode] ?? 0) + 1;
    }
    ksort($reasonDistribution);

    $selectedRows = array();
    $skippedRequeueOrigin = 0;
    foreach ($deadLetterRows as $row) {
        if (!$options['include_requeued_jobs'] && isRequeueOriginDeadLetter($row)) {
            $skippedRequeueOrigin++;
        }
        if (!matchesFilters($row, $options)) {
            continue;
        }
        $selectedRows[] = $row;
        if ($options['max'] > 0 && count($selectedRows) >= $options['max']) {
            break;
        }
    }

    $summary = array(
        'runtime_dir' => $options['runtime_dir'],
        'mode' => $options['summary_only'] ? 'summary_only' : ($options['dry_run'] ? 'dry_run' : 'requeue'),
        'filters' => array(
            'reason_codes' => $options['reason_codes'],
            'job_ids' => $options['job_ids'],
            'max' => $options['max'],
            'requeue_tag' => $options['requeue_tag'],
            'include_requeued_jobs' => $options['include_requeued_jobs'],
        ),
        'dead_letter_total' => count($deadLetterRows),
        'dead_letter_reason_distribution' => $reasonDistribution,
        'skipped_requeue_origin_rows' => $skippedRequeueOrigin,
        'selected_rows' => count($selectedRows),
        'processed_rows' => 0,
        'enqueued_rows' => 0,
        'duplicate_skipped_rows' => 0,
        'parse_failed_rows' => 0,
        'requeued_job_ids' => array(),
    );

    if ($options['summary_only']) {
        fwrite(STDOUT, json_encode($summary, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
        exit(0);
    }

    $existingDedupKeys = array();
    foreach (readJsonLines($jobsPath) as $jobRow) {
        $dedupKey = (string) ($jobRow['dedup_key'] ?? '');
        if ($dedupKey !== '') {
            $existingDedupKeys[$dedupKey] = true;
        }
    }

    foreach ($selectedRows as $deadLetterRow) {
        $summary['processed_rows']++;
        $jobPayload = is_array($deadLetterRow['job'] ?? null)
            ? $deadLetterRow['job']
            : array();
        if ($jobPayload === array()) {
            $summary['parse_failed_rows']++;
            continue;
        }

        $sourceJob = VerificationJob::fromArray($jobPayload);
        if ($sourceJob->jobId() === '' || $sourceJob->candidateId() === '') {
            $summary['parse_failed_rows']++;
            continue;
        }

        $baseReplayProfile = trim($sourceJob->replayProfile()) === '' ? 'local' : trim($sourceJob->replayProfile());
        $requeueProfile = $baseReplayProfile . '|requeue:' . $options['requeue_tag'] . ':' . $sourceJob->jobId();
        $jobId = 'requeue_' . substr(hash('sha256', implode('|', array(
            $sourceJob->jobId(),
            $sourceJob->candidateId(),
            $sourceJob->oracleType(),
            $requeueProfile,
        ))), 0, 24);

        $metadata = $sourceJob->metadata();
        $metadata['requeue_source_job_id'] = $sourceJob->jobId();
        $metadata['requeue_source_reason_code'] = (string) ($deadLetterRow['reason_code'] ?? '');
        $metadata['requeue_tag'] = $options['requeue_tag'];
        $metadata['requeue_requested_at'] = gmdate('c');

        $requeueJob = new VerificationJob(
            jobId: $jobId,
            candidateId: $sourceJob->candidateId(),
            sinkCategory: $sourceJob->sinkCategory(),
            oracleType: $sourceJob->oracleType(),
            replayProfile: $requeueProfile,
            createdAt: gmdate('c'),
            attemptCount: 0,
            status: 'pending',
            candidateSnapshot: $sourceJob->candidateSnapshot(),
            replayPlan: $sourceJob->replayPlan(),
            metadata: $metadata
        );

        $dedupKey = $requeueJob->dedupKey();
        if ($options['dry_run']) {
            if (isset($existingDedupKeys[$dedupKey])) {
                $summary['duplicate_skipped_rows']++;
                continue;
            }
            $existingDedupKeys[$dedupKey] = true;
            $summary['enqueued_rows']++;
            $summary['requeued_job_ids'][] = $requeueJob->jobId();
            continue;
        }

        $enqueued = $queue->enqueue($requeueJob);
        if (!$enqueued) {
            $summary['duplicate_skipped_rows']++;
            continue;
        }

        appendJsonLine($requeuesPath, array(
            'requeued_at' => gmdate('c'),
            'requeue_tag' => $options['requeue_tag'],
            'source_job_id' => $sourceJob->jobId(),
            'source_reason_code' => (string) ($deadLetterRow['reason_code'] ?? ''),
            'new_job_id' => $requeueJob->jobId(),
            'candidate_id' => $requeueJob->candidateId(),
            'sink_category' => $requeueJob->sinkCategory(),
            'oracle_type' => $requeueJob->oracleType(),
            'replay_profile' => $requeueJob->replayProfile(),
        ));
        $summary['enqueued_rows']++;
        $summary['requeued_job_ids'][] = $requeueJob->jobId();
    }

    fwrite(STDOUT, json_encode($summary, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    exit(0);
} catch (Throwable $error) {
    fwrite(STDERR, '[php_taint_trace] dead-letter requeue failure: ' . $error->getMessage() . PHP_EOL);
    exit(1);
}

