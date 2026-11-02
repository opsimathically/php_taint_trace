<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Oracle;

use PhpTaintTrace\Verification\Model\VerificationJob;
use PhpTaintTrace\Verification\Model\VerificationOutcome;
use PhpTaintTrace\Verification\Verifier\ReplayRequest;
use PhpTaintTrace\Verification\Verifier\ReplayResult;

final class SqliOracle implements OracleInterface
{
    public function supports(VerificationJob $job): bool
    {
        return $job->oracleType() === 'sqli_oracle' || $job->sinkCategory() === 'sqli';
    }

    public function verify(OracleContext $context): OracleDecision
    {
        $baseRequest = $this->baseRequest($context->job());
        if ($baseRequest === null) {
            return new OracleDecision(
                VerificationOutcome::INCONCLUSIVE,
                array('VERIFIER_SQLI_REQUEST_PARSE_FAILED'),
                'SQLi oracle could not parse replay request from candidate.',
                array()
            );
        }

        $policyDecision = ReplayPolicy::enforceMethodPolicy(
            $context->job(),
            $baseRequest,
            array('GET'),
            'VERIFIER_PHASE_D_GET_ONLY_POLICY',
            'Phase D verifier method policy rejected this request.'
        );
        if ($policyDecision !== null) {
            return $policyDecision;
        }

        $target = ReplayPolicy::resolveTargetParameter($context->job(), $baseRequest);
        if ($target === null) {
            return new OracleDecision(
                VerificationOutcome::INCONCLUSIVE,
                array('VERIFIER_SQLI_TARGET_PARAM_MISSING'),
                'SQLi oracle did not find a mutable parameter for replay.',
                array()
            );
        }

        $nonce = 'ptt_sqli_nonce_' . bin2hex(random_bytes(4));
        $strategies = array(
            array(
                'name' => 'union',
                'positive_label' => 'positive_union',
                'negative_label' => 'negative_control',
                'positive_payload' => sprintf("1 UNION SELECT '%s' -- ", $nonce),
                'negative_payload' => '1',
                'confirmed_reason' => 'VERIFIER_SQLI_UNION_CONFIRMED',
                'confirmed_summary' => 'SQLi oracle observed stable union nonce differential across repeated replay attempts.',
            ),
            array(
                'name' => 'direct_query',
                'positive_label' => 'positive_direct_query',
                'negative_label' => 'negative_direct_query',
                'positive_payload' => sprintf("SELECT '%s' AS username", $nonce),
                'negative_payload' => "SELECT 'ptt_sqli_control' AS username",
                'confirmed_reason' => 'VERIFIER_SQLI_DIRECT_QUERY_CONFIRMED',
                'confirmed_summary' => 'SQLi oracle observed stable direct-query nonce differential across repeated replay attempts.',
            ),
        );

        $attempts = array();
        $strategyArtifacts = array();
        foreach ($strategies as $strategy) {
            $rounds = array();
            $hasAmbiguousControlSignal = false;
            $hasNormalizationAmbiguity = false;
            $hasReflectionOnlySignal = false;
            for ($round = 1; $round <= $context->verificationRounds(); $round++) {
                $labelSuffix = $round === 1 ? '' : '_repeat';
                $positive = ReplayPolicy::mutateRequest(
                    $baseRequest,
                    $target,
                    (string) $strategy['positive_payload'],
                    (string) $strategy['positive_label'] . $labelSuffix
                );
                $negative = ReplayPolicy::mutateRequest(
                    $baseRequest,
                    $target,
                    (string) $strategy['negative_payload'],
                    (string) $strategy['negative_label'] . $labelSuffix
                );

                $positiveResult = $context->replayRunner()->replay($positive);
                $negativeResult = $context->replayRunner()->replay($negative);
                $attempts[] = $positiveResult;
                $attempts[] = $negativeResult;

                $positiveContainsNonce = str_contains($positiveResult->body(), $nonce);
                $negativeContainsNonce = str_contains($negativeResult->body(), $nonce);
                if (
                    (!$positiveContainsNonce && $this->containsNormalizedToken($positiveResult->body(), $nonce)) ||
                    (!$negativeContainsNonce && $this->containsNormalizedToken($negativeResult->body(), $nonce))
                ) {
                    $hasNormalizationAmbiguity = true;
                }

                $positiveTelemetry = $this->sqlTelemetryNonceSignal($positiveResult, $nonce);
                $negativeTelemetry = $this->sqlTelemetryNonceSignal($negativeResult, $nonce);
                $telemetryAvailable = $positiveTelemetry['available'] || $negativeTelemetry['available'];

                $bodySignal = $positiveContainsNonce && !$negativeContainsNonce;
                $sqlSignal = $positiveTelemetry['contains_nonce'] && !$negativeTelemetry['contains_nonce'];
                $signal = $telemetryAvailable ? $sqlSignal : $bodySignal;
                if ($telemetryAvailable && $bodySignal && !$sqlSignal) {
                    $hasReflectionOnlySignal = true;
                }
                if ($telemetryAvailable) {
                    if ($positiveTelemetry['contains_nonce'] && $negativeTelemetry['contains_nonce']) {
                        $hasAmbiguousControlSignal = true;
                    }
                } elseif ($positiveContainsNonce && $negativeContainsNonce) {
                    $hasAmbiguousControlSignal = true;
                }

                $rounds[] = array(
                    'round' => $round,
                    'positive' => $positiveResult,
                    'negative' => $negativeResult,
                    'signal' => $signal,
                    'telemetry_available' => $telemetryAvailable,
                    'positive_sql_telemetry' => $positiveTelemetry['observations'],
                    'negative_sql_telemetry' => $negativeTelemetry['observations'],
                );
            }

            $strategyArtifacts[] = array(
                'strategy' => (string) $strategy['name'],
                'rounds' => array_map(
                    static fn (array $round): array => array(
                        'round' => $round['round'],
                        'positive' => $round['positive']->toArray(),
                        'negative' => $round['negative']->toArray(),
                        'telemetry_available' => $round['telemetry_available'],
                        'positive_sql_telemetry' => $round['positive_sql_telemetry'],
                        'negative_sql_telemetry' => $round['negative_sql_telemetry'],
                    ),
                    $rounds
                ),
            );

            foreach ($rounds as $round) {
                if (!$round['positive']->isSuccess() || !$round['negative']->isSuccess()) {
                    $artifact = $context->writeArtifact('sqli_oracle', array(
                        'target_parameter' => $target['parameter'],
                        'target_location' => $target['location'],
                        'nonce' => $nonce,
                        'strategies' => $strategyArtifacts,
                    ));

                    return new OracleDecision(
                        VerificationOutcome::REPLAY_FAILED,
                        array('VERIFIER_SQLI_REPLAY_ERROR'),
                        'SQLi oracle replay failed for one or more attempts.',
                        $attempts,
                        array($artifact)
                    );
                }
            }

            $signals = array_map(
                static fn (array $round): bool => (bool) $round['signal'],
                $rounds
            );
            if ($this->hasSignalInstability($signals)) {
                $artifact = $context->writeArtifact('sqli_oracle', array(
                    'target_parameter' => $target['parameter'],
                    'target_location' => $target['location'],
                    'nonce' => $nonce,
                    'strategies' => $strategyArtifacts,
                ));

                return new OracleDecision(
                    VerificationOutcome::NOT_CONFIRMED,
                    array('VERIFIER_SQLI_RESPONSE_INSTABILITY'),
                    'SQLi oracle observed unstable exploit differential across repeated replay attempts.',
                    $attempts,
                    array($artifact)
                );
            }

            if ($hasNormalizationAmbiguity) {
                $artifact = $context->writeArtifact('sqli_oracle', array(
                    'target_parameter' => $target['parameter'],
                    'target_location' => $target['location'],
                    'nonce' => $nonce,
                    'strategies' => $strategyArtifacts,
                ));

                return new OracleDecision(
                    VerificationOutcome::NOT_CONFIRMED,
                    array('VERIFIER_SQLI_NORMALIZATION_AMBIGUITY'),
                    'SQLi oracle observed nonce indicators only after response normalization.',
                    $attempts,
                    array($artifact)
                );
            }

            if ($hasReflectionOnlySignal) {
                $artifact = $context->writeArtifact('sqli_oracle', array(
                    'target_parameter' => $target['parameter'],
                    'target_location' => $target['location'],
                    'nonce' => $nonce,
                    'strategies' => $strategyArtifacts,
                ));

                return new OracleDecision(
                    VerificationOutcome::NOT_CONFIRMED,
                    array('VERIFIER_SQLI_REFLECTION_ONLY_SIGNAL'),
                    'SQLi oracle observed response reflection without SQL execution nonce evidence.',
                    $attempts,
                    array($artifact)
                );
            }

            if ($this->allTrue($signals)) {
                $artifact = $context->writeArtifact('sqli_oracle', array(
                    'target_parameter' => $target['parameter'],
                    'target_location' => $target['location'],
                    'nonce' => $nonce,
                    'strategies' => $strategyArtifacts,
                ));

                return new OracleDecision(
                    VerificationOutcome::CONFIRMED,
                    array((string) $strategy['confirmed_reason']),
                    (string) $strategy['confirmed_summary'],
                    $attempts,
                    array($artifact)
                );
            }

            if ($hasAmbiguousControlSignal) {
                $artifact = $context->writeArtifact('sqli_oracle', array(
                    'target_parameter' => $target['parameter'],
                    'target_location' => $target['location'],
                    'nonce' => $nonce,
                    'strategies' => $strategyArtifacts,
                ));

                return new OracleDecision(
                    VerificationOutcome::NOT_CONFIRMED,
                    array('VERIFIER_SQLI_AMBIGUOUS_CONTROL_SIGNAL'),
                    'SQLi oracle observed nonce in both positive and control replay responses.',
                    $attempts,
                    array($artifact)
                );
            }
        }

        $artifact = $context->writeArtifact('sqli_oracle', array(
            'target_parameter' => $target['parameter'],
            'target_location' => $target['location'],
            'nonce' => $nonce,
            'strategies' => $strategyArtifacts,
        ));

        return new OracleDecision(
            VerificationOutcome::NOT_CONFIRMED,
            array('VERIFIER_SQLI_WEAK_DIFFERENTIAL', 'VERIFIER_SQLI_CONTROL_MISMATCH'),
            'SQLi oracle did not observe a strong, repeatable nonce differential.',
            $attempts,
            array($artifact)
        );
    }

    private function baseRequest(VerificationJob $job): ?ReplayRequest
    {
        return ReplayRequest::fromReplayPlan($job->sinkCategory(), $job->replayPlan());
    }

    private function hasSignalInstability(array $roundSignals): bool
    {
        return count(array_unique($roundSignals, SORT_REGULAR)) > 1;
    }

    private function allTrue(array $signals): bool
    {
        if ($signals === array()) {
            return false;
        }

        foreach ($signals as $signal) {
            if ($signal !== true) {
                return false;
            }
        }

        return true;
    }

    private function containsNormalizedToken(string $body, string $token): bool
    {
        $variants = array(
            $body,
            urldecode($body),
            html_entity_decode($body, ENT_QUOTES | ENT_HTML5),
        );

        foreach ($variants as $variant) {
            if (str_contains($variant, $token)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return array{available: bool, contains_nonce: bool, observations: array<int, array<string, mixed>>}
     */
    private function sqlTelemetryNonceSignal(ReplayResult $result, string $nonce): array
    {
        $metadata = $result->metadata();
        $replayId = is_scalar($metadata['replay_id'] ?? null) ? trim((string) $metadata['replay_id']) : '';
        if ($replayId === '' || !SqliReplayTelemetryStore::isValidReplayId($replayId)) {
            return array(
                'available' => false,
                'contains_nonce' => false,
                'observations' => array(),
            );
        }

        $observations = SqliReplayTelemetryStore::read($replayId);
        SqliReplayTelemetryStore::delete($replayId);

        if ($observations === array()) {
            return array(
                'available' => false,
                'contains_nonce' => false,
                'observations' => array(),
            );
        }

        foreach ($observations as $observation) {
            $sql = is_array($observation['sql'] ?? null) ? $observation['sql'] : array();
            if ($this->sqlPayloadContainsToken($sql, $nonce)) {
                return array(
                    'available' => true,
                    'contains_nonce' => true,
                    'observations' => $observations,
                );
            }
        }

        return array(
            'available' => true,
            'contains_nonce' => false,
            'observations' => $observations,
        );
    }

    /**
     * @param array<string, mixed> $sql
     */
    private function sqlPayloadContainsToken(array $sql, string $token): bool
    {
        $query = $sql['query'] ?? null;
        if (is_string($query) && str_contains($query, $token)) {
            return true;
        }

        $statementName = $sql['statement_name'] ?? null;
        if (is_string($statementName) && str_contains($statementName, $token)) {
            return true;
        }

        return $this->containsTokenRecursively($sql['parameters'] ?? null, $token);
    }

    private function containsTokenRecursively(mixed $value, string $token): bool
    {
        if (is_string($value)) {
            return str_contains($value, $token);
        }

        if (is_array($value)) {
            foreach ($value as $entry) {
                if ($this->containsTokenRecursively($entry, $token)) {
                    return true;
                }
            }
        }

        return false;
    }
}
