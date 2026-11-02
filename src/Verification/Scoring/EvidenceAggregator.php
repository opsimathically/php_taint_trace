<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Scoring;

use PhpTaintTrace\Verification\Model\VerificationJob;
use PhpTaintTrace\Verification\Model\VerificationOutcome;
use PhpTaintTrace\Verification\Model\VerificationResult;

final class EvidenceAggregator
{
    /**
     * @return array{
     *   reachability_score: float,
     *   exploit_score: float,
     *   sanitization_score: float,
     *   environment_score: float,
     *   repro_score: float,
     *   reason_codes: string[],
     *   metadata: array<string, mixed>
     * }
     */
    public function aggregate(VerificationJob $job, VerificationResult $result): array
    {
        $candidate = $job->candidateSnapshot();
        $taintEvidence = is_array($candidate['taint_evidence'] ?? null) ? $candidate['taint_evidence'] : array();
        $detectorEvidence = is_array($candidate['detector_evidence'] ?? null) ? $candidate['detector_evidence'] : array();
        $sinkEvidence = is_array($candidate['sink_evidence'] ?? null) ? $candidate['sink_evidence'] : array();
        $sinkMetadata = is_array($sinkEvidence['metadata'] ?? null) ? $sinkEvidence['metadata'] : array();
        $stacktrace = $this->normalizeStacktrace($sinkMetadata['stacktrace'] ?? null);

        $hasTaint = (bool) ($taintEvidence['has_taint'] ?? false);
        $findingCount = (int) ($detectorEvidence['finding_count'] ?? 0);
        $detectorCount = count(is_array($detectorEvidence['detectors'] ?? null) ? $detectorEvidence['detectors'] : array());

        $reachabilityScore = 0.45;
        if ($hasTaint) {
            $reachabilityScore += 0.30;
        }
        if ($findingCount > 0) {
            $reachabilityScore += 0.15;
        }
        if ($detectorCount > 1) {
            $reachabilityScore += 0.10;
        }

        $exploitScore = match ($result->outcome()) {
            VerificationOutcome::CONFIRMED => 1.0,
            VerificationOutcome::NOT_CONFIRMED => 0.0,
            VerificationOutcome::REPLAY_FAILED => 0.10,
            VerificationOutcome::BLOCKED_BY_POLICY => 0.20,
            VerificationOutcome::INCONCLUSIVE => 0.35,
        };

        $environmentScore = match ($result->outcome()) {
            VerificationOutcome::BLOCKED_BY_POLICY => 0.0,
            VerificationOutcome::REPLAY_FAILED => 0.25,
            default => 1.0,
        };

        $sanitizationScore = $this->computeSanitizationScore(
            array_merge($this->candidateReasonCodes($candidate), $result->reasonCodes())
        );

        $transcripts = $result->replayTranscripts();
        $reproScore = 0.30;
        if ($transcripts !== array()) {
            $successful = 0;
            foreach ($transcripts as $transcript) {
                $statusCode = $transcript['status_code'] ?? null;
                $error = $transcript['error'] ?? null;
                if (is_int($statusCode) && $error === null) {
                    $successful++;
                }
            }

            $reproScore = $successful / max(1, count($transcripts));
        } elseif ($result->outcome() === VerificationOutcome::CONFIRMED) {
            $reproScore = 1.0;
        }

        $metadata = array(
            'finding_count' => $findingCount,
            'detector_count' => $detectorCount,
            'has_taint' => $hasTaint,
            'replay_attempt_count' => count($transcripts),
        );
        $reproduction = $this->buildReproductionMetadata(
            $candidate,
            $job->replayPlan(),
            $sinkMetadata,
            $transcripts
        );
        if ($reproduction !== array()) {
            $metadata['reproduction'] = $reproduction;
            if (is_string($reproduction['request_method'] ?? null)) {
                $metadata['request_method'] = $reproduction['request_method'];
            }
            if (is_string($reproduction['request_uri'] ?? null)) {
                $metadata['request_uri'] = $reproduction['request_uri'];
            }
            if (is_string($reproduction['sink_name'] ?? null)) {
                $metadata['sink_name'] = $reproduction['sink_name'];
            }
            if (is_string($reproduction['sink_category'] ?? null)) {
                $metadata['sink_category'] = $reproduction['sink_category'];
            }
        }
        if ($stacktrace !== array()) {
            $metadata['stacktrace'] = $stacktrace;
            if (is_string($sinkMetadata['stacktrace_captured_at'] ?? null)) {
                $metadata['stacktrace_captured_at'] = $sinkMetadata['stacktrace_captured_at'];
            }
        }
        if (is_array($sinkMetadata['sql'] ?? null) && $sinkMetadata['sql'] !== array()) {
            $metadata['sql'] = $sinkMetadata['sql'];
        }
        if (is_array($sinkMetadata['rce'] ?? null) && $sinkMetadata['rce'] !== array()) {
            $metadata['rce'] = $sinkMetadata['rce'];
        }

        return array(
            'reachability_score' => $this->clamp($reachabilityScore),
            'exploit_score' => $this->clamp($exploitScore),
            'sanitization_score' => $this->clamp($sanitizationScore),
            'environment_score' => $this->clamp($environmentScore),
            'repro_score' => $this->clamp($reproScore),
            'reason_codes' => array_values(array_unique(array_merge(
                $this->candidateReasonCodes($candidate),
                $result->reasonCodes()
            ))),
            'metadata' => $metadata,
        );
    }

    /**
     * @param array<string, mixed> $candidate
     * @return string[]
     */
    private function candidateReasonCodes(array $candidate): array
    {
        if (!is_array($candidate['reason_codes'] ?? null)) {
            return array();
        }

        return array_values(array_filter(
            array_map(static fn (mixed $code): string => (string) $code, $candidate['reason_codes']),
            static fn (string $code): bool => $code !== ''
        ));
    }

    /**
     * @param string[] $reasonCodes
     */
    private function computeSanitizationScore(array $reasonCodes): float
    {
        $trustedProofCodes = array(
            'SANITIZER_TRUSTED_PROOF_PRESENT',
            'VALIDATOR_TRUSTED_PROOF_PRESENT',
            'CONFIDENCE_SANITIZER_TRUSTED_PROOF',
        );

        foreach ($reasonCodes as $reasonCode) {
            if (in_array($reasonCode, $trustedProofCodes, true)) {
                return 1.0;
            }
        }

        return 0.0;
    }

    private function clamp(float $value): float
    {
        return max(0.0, min(1.0, $value));
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    private function normalizeStacktrace(mixed $value): array
    {
        if (!is_array($value)) {
            return array();
        }

        $frames = array();
        foreach ($value as $frame) {
            if (!is_array($frame)) {
                continue;
            }

            $level = $frame['level'] ?? null;
            if (!is_int($level) || $level < 0) {
                continue;
            }

            $normalized = array('level' => $level);
            if (is_string($frame['where'] ?? null) && trim((string) $frame['where']) !== '') {
                $normalized['where'] = trim((string) $frame['where']);
            }
            if (is_string($frame['file_uri'] ?? null) && trim((string) $frame['file_uri']) !== '') {
                $normalized['file_uri'] = trim((string) $frame['file_uri']);
            }
            if (is_int($frame['lineno'] ?? null) && (int) $frame['lineno'] > 0) {
                $normalized['lineno'] = (int) $frame['lineno'];
            }
            if (is_string($frame['type'] ?? null) && trim((string) $frame['type']) !== '') {
                $normalized['type'] = trim((string) $frame['type']);
            }

            $frames[] = $normalized;
            if (count($frames) >= 24) {
                break;
            }
        }

        return $frames;
    }

    /**
     * @param array<string, mixed> $candidate
     * @param array<string, mixed> $replayPlan
     * @param array<string, mixed> $sinkMetadata
     * @param array<int, array<string, mixed>> $transcripts
     * @return array<string, mixed>
     */
    private function buildReproductionMetadata(
        array $candidate,
        array $replayPlan,
        array $sinkMetadata,
        array $transcripts
    ): array {
        $requestEvidence = is_array($candidate['request_evidence'] ?? null) ? $candidate['request_evidence'] : array();
        $requestMetadata = is_array($requestEvidence['metadata'] ?? null) ? $requestEvidence['metadata'] : array();
        $sinkEvidence = is_array($candidate['sink_evidence'] ?? null) ? $candidate['sink_evidence'] : array();

        $requestMethod = $this->firstNonEmptyString(
            $requestEvidence['request_method'] ?? null,
            $replayPlan['request_method'] ?? null
        );
        $requestUri = $this->firstNonEmptyString(
            $requestEvidence['request_uri'] ?? null,
            $replayPlan['request_uri'] ?? null
        );
        $sinkName = $this->firstNonEmptyString(
            $candidate['sink_name'] ?? null,
            $sinkEvidence['sink_name'] ?? null
        );
        $sinkCategory = $this->firstNonEmptyString(
            $candidate['sink_category'] ?? null,
            $sinkEvidence['sink_category'] ?? null
        );

        $payloads = $this->normalizePayloads($sinkMetadata['payloads'] ?? null);
        if ($payloads === array()) {
            $payloads = $this->payloadLabelsFromReplayTranscripts($transcripts);
        }

        $metadata = array();
        if ($requestMethod !== null) {
            $metadata['request_method'] = $requestMethod;
        }
        if ($requestUri !== null) {
            $metadata['request_uri'] = $requestUri;
        }
        if ($sinkName !== null) {
            $metadata['sink_name'] = $sinkName;
        }
        if ($sinkCategory !== null) {
            $metadata['sink_category'] = $sinkCategory;
        }
        if ($payloads !== array()) {
            $metadata['payloads'] = $payloads;
        }

        $optionalStringFields = array(
            'template_name' => $sinkMetadata['template_name'] ?? null,
            'mutation_target' => $sinkMetadata['mutation_target'] ?? null,
            'reset_value' => $sinkMetadata['reset_value'] ?? null,
            'target_query_param' => $replayPlan['target_query_param'] ?? null,
            'target_body_param' => $replayPlan['target_body_param'] ?? null,
            'target_param_location' => $replayPlan['target_param_location'] ?? null,
            'correlation_id' => $requestMetadata['correlation_id'] ?? null,
            'request_id' => $requestMetadata['request_id'] ?? null,
            'finding_id' => $requestMetadata['finding_id'] ?? null,
            'trace_id' => $requestMetadata['trace_id'] ?? null,
        );

        foreach ($optionalStringFields as $key => $value) {
            $normalized = $this->firstNonEmptyString($value);
            if ($normalized !== null) {
                $metadata[$key] = $normalized;
            }
        }

        return $metadata;
    }

    private function firstNonEmptyString(mixed ...$values): ?string
    {
        foreach ($values as $value) {
            if (!is_scalar($value)) {
                continue;
            }

            $normalized = trim((string) $value);
            if ($normalized === '') {
                continue;
            }

            return $normalized;
        }

        return null;
    }

    /**
     * @return string[]
     */
    private function normalizePayloads(mixed $value): array
    {
        if (!is_array($value)) {
            return array();
        }

        $payloads = array();
        foreach ($value as $entry) {
            if (!is_scalar($entry)) {
                continue;
            }

            $normalized = trim((string) $entry);
            if ($normalized === '') {
                continue;
            }

            $payloads[] = $normalized;
        }

        return array_values(array_unique($payloads));
    }

    /**
     * @param array<int, array<string, mixed>> $transcripts
     * @return string[]
     */
    private function payloadLabelsFromReplayTranscripts(array $transcripts): array
    {
        $labels = array();
        foreach ($transcripts as $transcript) {
            if (!is_array($transcript)) {
                continue;
            }

            $request = is_array($transcript['request'] ?? null) ? $transcript['request'] : array();
            $payloadLabel = $this->firstNonEmptyString($request['payload_label'] ?? null);
            if ($payloadLabel === null) {
                continue;
            }

            $labels[] = $payloadLabel;
        }

        return array_values(array_unique($labels));
    }
}
