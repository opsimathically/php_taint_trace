<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Verifier;

use PhpTaintTrace\Verification\Model\VerificationResult;
use PhpTaintTrace\Verification\Oracle\OracleContext;
use PhpTaintTrace\Verification\Oracle\OracleDecision;
use PhpTaintTrace\Verification\Oracle\OracleInterface;
use PhpTaintTrace\Verification\Scoring\DecisionPolicy;
use PhpTaintTrace\Verification\Scoring\EvidenceAggregator;
use PhpTaintTrace\Verification\Scoring\RiskScorer;
use PhpTaintTrace\Verification\Storage\DecisionStoreInterface;

final class VerificationWorker
{
    /**
     * @var OracleInterface[]
     */
    private array $oracles;
    private readonly EvidenceAggregator $evidenceAggregator;
    private readonly RiskScorer $riskScorer;
    private readonly DecisionPolicy $decisionPolicy;

    public function __construct(
        private readonly VerificationQueueInterface $queue,
        private readonly ReplayRunnerInterface $replayRunner,
        array $oracles,
        private readonly int $maxAttempts = 2,
        private readonly string $artifactDirectory = '.php_taint_trace_runtime/verifier/artifacts',
        private readonly int $verificationRounds = 2,
        private readonly ?DecisionStoreInterface $decisionStore = null,
        ?EvidenceAggregator $evidenceAggregator = null,
        ?RiskScorer $riskScorer = null,
        ?DecisionPolicy $decisionPolicy = null
    ) {
        $this->oracles = array_values($oracles);
        $this->evidenceAggregator = $evidenceAggregator ?? new EvidenceAggregator();
        $this->riskScorer = $riskScorer ?? new RiskScorer();
        $this->decisionPolicy = $decisionPolicy ?? new DecisionPolicy();
    }

    public function process(int $batchSize = 50): int
    {
        $jobs = $this->queue->dequeueBatch($batchSize);
        $processed = 0;

        foreach ($jobs as $job) {
            $processed++;
            $this->processJob($job);
        }

        return $processed;
    }

    private function processJob(\PhpTaintTrace\Verification\Model\VerificationJob $job): void
    {
        $oracle = $this->resolveOracle($job);
        if ($oracle === null) {
            $this->queue->markFailed($job, 'VERIFIER_ORACLE_UNAVAILABLE', array(
                'failure_stage' => 'resolve_oracle',
                'max_attempts' => $this->maxAttempts,
            ));
            return;
        }

        $attempt = 0;
        while ($attempt < $this->maxAttempts) {
            $attempt++;
            $attemptJob = $job->withAttemptCount($attempt)->withStatus('processing');

            try {
                $decision = $oracle->verify(new OracleContext(
                    $attemptJob,
                    $this->replayRunner,
                    $this->artifactDirectory,
                    $this->verificationRounds
                ));
                $result = $this->buildResult($attemptJob, $decision);
                $this->queue->markCompleted($attemptJob->withStatus('completed'), $result);
                $this->scoreAndPersistDecision($attemptJob, $result);
                return;
            } catch (\Throwable $error) {
                if ($attempt >= $this->maxAttempts) {
                    $this->queue->markFailed(
                        $attemptJob->withStatus('failed'),
                        'VERIFIER_EXCEPTION_RETRY_EXHAUSTED',
                        array(
                            'failure_stage' => 'oracle_verify',
                            'max_attempts' => $this->maxAttempts,
                            'exception_class' => $error::class,
                            'exception_message' => $error->getMessage(),
                        )
                    );
                    return;
                }
            }
        }
    }

    private function resolveOracle(\PhpTaintTrace\Verification\Model\VerificationJob $job): ?OracleInterface
    {
        foreach ($this->oracles as $oracle) {
            if ($oracle->supports($job)) {
                return $oracle;
            }
        }

        return null;
    }

    private function buildResult(
        \PhpTaintTrace\Verification\Model\VerificationJob $job,
        OracleDecision $decision
    ): VerificationResult {
        $metadata = array_merge(
            $decision->metadata(),
            array(
                'sink_category' => $job->sinkCategory(),
                'oracle_type' => $job->oracleType(),
                'attempt_count' => $job->attemptCount(),
            )
        );

        if (!is_array($metadata['stacktrace'] ?? null)) {
            $sinkStacktrace = $this->extractSinkStacktraceFromJob($job);
            if ($sinkStacktrace !== array()) {
                $metadata['stacktrace'] = $sinkStacktrace;
            }
        }
        if (!is_array($metadata['sql'] ?? null)) {
            $sinkSqlMetadata = $this->extractSinkSqlMetadataFromJob($job);
            if ($sinkSqlMetadata !== array()) {
                $metadata['sql'] = $sinkSqlMetadata;
            }
        }
        if (!is_array($metadata['rce'] ?? null)) {
            $sinkRceMetadata = $this->extractSinkRceMetadataFromJob($job);
            if ($sinkRceMetadata !== array()) {
                $metadata['rce'] = $sinkRceMetadata;
            }
        }

        return new VerificationResult(
            jobId: $job->jobId(),
            candidateId: $job->candidateId(),
            outcome: $decision->outcome(),
            reasonCodes: $decision->reasonCodes(),
            summary: $decision->summary(),
            artifacts: $decision->artifacts(),
            replayTranscripts: array_map(
                static fn (ReplayResult $result): array => $result->toArray(),
                $decision->replayAttempts()
            ),
            createdAt: gmdate('c'),
            metadata: $metadata
        );
    }

    private function scoreAndPersistDecision(
        \PhpTaintTrace\Verification\Model\VerificationJob $job,
        VerificationResult $result
    ): void {
        if ($this->decisionStore === null) {
            return;
        }

        try {
            $aggregate = $this->evidenceAggregator->aggregate($job, $result);
            $scoreBreakdown = $this->riskScorer->score(
                (float) ($aggregate['reachability_score'] ?? 0.0),
                (float) ($aggregate['exploit_score'] ?? 0.0),
                (float) ($aggregate['sanitization_score'] ?? 0.0),
                (float) ($aggregate['environment_score'] ?? 0.0),
                (float) ($aggregate['repro_score'] ?? 0.0)
            );

            $decision = $this->decisionPolicy->buildDecision(
                $job,
                $result,
                $scoreBreakdown,
                is_array($aggregate['reason_codes'] ?? null) ? $aggregate['reason_codes'] : array(),
                is_array($aggregate['metadata'] ?? null) ? $aggregate['metadata'] : array()
            );

            $stored = $this->decisionStore->persist($decision);
            if (!$stored) {
                error_log(sprintf(
                    '[php_taint_trace] SCORING_DECISION_DUPLICATE_SKIPPED decision_id=%s job_id=%s',
                    $decision->decisionId(),
                    $decision->jobId()
                ));
            }
        } catch (\Throwable $error) {
            error_log('[php_taint_trace] scoring pipeline failure: ' . $error->getMessage());
        }
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    private function extractSinkStacktraceFromJob(\PhpTaintTrace\Verification\Model\VerificationJob $job): array
    {
        $candidate = $job->candidateSnapshot();
        $sinkEvidence = is_array($candidate['sink_evidence'] ?? null) ? $candidate['sink_evidence'] : array();
        $sinkMetadata = is_array($sinkEvidence['metadata'] ?? null) ? $sinkEvidence['metadata'] : array();
        $stacktrace = $sinkMetadata['stacktrace'] ?? null;

        if (!is_array($stacktrace)) {
            return array();
        }

        $frames = array();
        foreach ($stacktrace as $frame) {
            if (!is_array($frame) || !is_int($frame['level'] ?? null)) {
                continue;
            }

            $frames[] = $frame;
            if (count($frames) >= 24) {
                break;
            }
        }

        return $frames;
    }

    /**
     * @return array<string, mixed>
     */
    private function extractSinkSqlMetadataFromJob(\PhpTaintTrace\Verification\Model\VerificationJob $job): array
    {
        $candidate = $job->candidateSnapshot();
        $sinkEvidence = is_array($candidate['sink_evidence'] ?? null) ? $candidate['sink_evidence'] : array();
        $sinkMetadata = is_array($sinkEvidence['metadata'] ?? null) ? $sinkEvidence['metadata'] : array();
        $sql = $sinkMetadata['sql'] ?? null;

        return is_array($sql) ? $sql : array();
    }

    /**
     * @return array<string, mixed>
     */
    private function extractSinkRceMetadataFromJob(\PhpTaintTrace\Verification\Model\VerificationJob $job): array
    {
        $candidate = $job->candidateSnapshot();
        $sinkEvidence = is_array($candidate['sink_evidence'] ?? null) ? $candidate['sink_evidence'] : array();
        $sinkMetadata = is_array($sinkEvidence['metadata'] ?? null) ? $sinkEvidence['metadata'] : array();
        $rce = $sinkMetadata['rce'] ?? null;

        return is_array($rce) ? $rce : array();
    }
}
