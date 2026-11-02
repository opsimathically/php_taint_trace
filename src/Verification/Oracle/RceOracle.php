<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Oracle;

use PhpTaintTrace\Verification\Model\VerificationJob;
use PhpTaintTrace\Verification\Model\VerificationOutcome;
use PhpTaintTrace\Verification\Verifier\RequestParamPolicy;
use PhpTaintTrace\Verification\Verifier\ReplayRequest;

final class RceOracle implements OracleInterface
{
    private const MARKER_PREFIX = 'ptt_rce_';

    public function supports(VerificationJob $job): bool
    {
        return $job->oracleType() === 'rce_oracle' || $job->sinkCategory() === 'rce';
    }

    public function verify(OracleContext $context): OracleDecision
    {
        $baseRequest = $this->baseRequest($context->job());
        if ($baseRequest === null) {
            return new OracleDecision(
                VerificationOutcome::INCONCLUSIVE,
                array('VERIFIER_RCE_REQUEST_PARSE_FAILED'),
                'RCE oracle could not parse replay request from candidate.',
                array()
            );
        }

        $policyDecision = ReplayPolicy::enforceMethodPolicy(
            $context->job(),
            $baseRequest,
            array('GET'),
            'VERIFIER_PHASE_B_GET_ONLY_POLICY',
            'Phase B verifier method policy rejected this request.'
        );
        if ($policyDecision !== null) {
            return $policyDecision;
        }

        $target = ReplayPolicy::resolveTargetParameter($context->job(), $baseRequest);
        if ($target === null) {
            return new OracleDecision(
                VerificationOutcome::INCONCLUSIVE,
                array('VERIFIER_RCE_TARGET_PARAM_MISSING'),
                'RCE oracle did not find a mutable parameter for replay.',
                array()
            );
        }

        $challenge = $this->buildChallengeSet();
        $strategies = $this->payloadStrategiesForReplayPlan($context->job(), $challenge);
        $artifactPayload = array(
            'target_parameter' => $target['parameter'],
            'target_location' => $target['location'],
            'challenge' => $challenge,
            'strategies' => array(),
        );
        $allAttempts = array();
        $bestFailure = null;

        foreach ($strategies as $strategy) {
            $rounds = array();
            $attempts = array();
            for ($round = 1; $round <= $context->verificationRounds(); $round++) {
                $labelSuffix = $round === 1 ? '' : '_repeat';
                $positive = ReplayPolicy::mutateRequest(
                    $baseRequest,
                    $target,
                    $strategy['positive_payload'],
                    'positive_nonce' . $labelSuffix
                );
                $negative = ReplayPolicy::mutateRequest(
                    $baseRequest,
                    $target,
                    $strategy['negative_payload'],
                    'negative_control' . $labelSuffix
                );

                $positiveResult = $context->replayRunner()->replay($positive);
                $negativeResult = $context->replayRunner()->replay($negative);
                $attempts[] = $positiveResult;
                $attempts[] = $negativeResult;

                $rounds[] = array(
                    'round' => $round,
                    'positive' => $positiveResult,
                    'negative' => $negativeResult,
                );
            }

            $allAttempts = array_merge($allAttempts, $attempts);
            $artifactPayload['strategies'][] = array(
                'name' => $strategy['name'],
                'expected_positive_token' => $strategy['expected_positive_token'],
                'rounds' => array_map(
                    static fn (array $round): array => array(
                        'round' => $round['round'],
                        'positive' => $round['positive']->toArray(),
                        'negative' => $round['negative']->toArray(),
                    ),
                    $rounds
                ),
            );

            foreach ($rounds as $round) {
                if (!$round['positive']->isSuccess() || !$round['negative']->isSuccess()) {
                    $artifact = $context->writeArtifact('rce_oracle', $artifactPayload);
                    return new OracleDecision(
                        VerificationOutcome::REPLAY_FAILED,
                        array('VERIFIER_RCE_REPLAY_ERROR'),
                        'RCE oracle replay failed for one or more attempts.',
                        $allAttempts,
                        array($artifact)
                    );
                }
            }

            $expectedToken = $strategy['expected_positive_token'];
            $roundSignals = array();
            $hasAmbiguousControlSignal = false;
            $hasNormalizationAmbiguity = false;

            foreach ($rounds as $round) {
                $positiveContainsExpectedToken = str_contains($round['positive']->body(), $expectedToken);
                $negativeContainsExpectedToken = str_contains($round['negative']->body(), $expectedToken);
                $roundSignals[] = $positiveContainsExpectedToken && !$negativeContainsExpectedToken;

                if ($positiveContainsExpectedToken && $negativeContainsExpectedToken) {
                    $hasAmbiguousControlSignal = true;
                }

                if (
                    (!$positiveContainsExpectedToken && $this->containsNormalizedToken($round['positive']->body(), $expectedToken)) ||
                    (!$negativeContainsExpectedToken && $this->containsNormalizedToken($round['negative']->body(), $expectedToken))
                ) {
                    $hasNormalizationAmbiguity = true;
                }
            }

            if ($this->hasSignalInstability($roundSignals)) {
                $bestFailure ??= array(
                    'reasonCodes' => array('VERIFIER_RCE_RESPONSE_INSTABILITY'),
                    'summary' => 'RCE oracle observed unstable exploit differential across repeated replay attempts.',
                );
                continue;
            }

            if ($hasNormalizationAmbiguity) {
                $bestFailure ??= array(
                    'reasonCodes' => array('VERIFIER_RCE_NORMALIZATION_AMBIGUITY'),
                    'summary' => 'RCE oracle observed transformed token indicators only after response normalization.',
                );
                continue;
            }

            if ($this->allTrue($roundSignals)) {
                $artifact = $context->writeArtifact('rce_oracle', $artifactPayload);
                return new OracleDecision(
                    VerificationOutcome::CONFIRMED,
                    array('VERIFIER_RCE_NONCE_CONFIRMED'),
                    'RCE oracle observed stable transformed-token differential across repeated replay attempts.',
                    $allAttempts,
                    array($artifact)
                );
            }

            if ($hasAmbiguousControlSignal) {
                $bestFailure ??= array(
                    'reasonCodes' => array('VERIFIER_RCE_AMBIGUOUS_CONTROL_SIGNAL'),
                    'summary' => 'RCE oracle observed transformed token in both positive and control replay responses.',
                );
                continue;
            }

            $bestFailure ??= array(
                'reasonCodes' => array('VERIFIER_RCE_WEAK_DIFFERENTIAL', 'VERIFIER_RCE_CONTROL_MISMATCH'),
                'summary' => 'RCE oracle did not observe a strong, repeatable transformed-token differential.',
            );
        }

        $artifact = $context->writeArtifact('rce_oracle', $artifactPayload);
        return new OracleDecision(
            VerificationOutcome::NOT_CONFIRMED,
            $bestFailure['reasonCodes'] ?? array('VERIFIER_RCE_WEAK_DIFFERENTIAL', 'VERIFIER_RCE_CONTROL_MISMATCH'),
            $bestFailure['summary'] ?? 'RCE oracle did not observe a strong, repeatable transformed-token differential.',
            $allAttempts,
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
     * @return array{positive_number: int, negative_number: int, delta: int}
     */
    private function buildChallengeSet(): array
    {
        $positive = random_int(100000, 999999);
        do {
            $negative = random_int(100000, 999999);
        } while ($negative === $positive);

        return array(
            'positive_number' => $positive,
            'negative_number' => $negative,
            'delta' => random_int(700, 9700),
        );
    }

    /**
     * @param array{positive_number: int, negative_number: int, delta: int} $challenge
     * @return array<int, array{name: string, positive_payload: string, negative_payload: string, expected_positive_token: string}>
     */
    private function payloadStrategiesForReplayPlan(VerificationJob $job, array $challenge): array
    {
        $positiveTransformed = $challenge['positive_number'] + $challenge['delta'];
        $expectedPositive = self::MARKER_PREFIX . (string) $positiveTransformed;

        $requestUri = (string) ($job->replayPlan()['request_uri'] ?? '');
        if ($this->usesEvalStylePayloads($job, $requestUri)) {
            return array(array(
                'name' => 'php_arithmetic_marker',
                'positive_payload' => "echo '" . self::MARKER_PREFIX . "'.(" . $challenge['positive_number'] . '+' . $challenge['delta'] . ');',
                'negative_payload' => "echo '" . self::MARKER_PREFIX . "'.(" . $challenge['negative_number'] . '+' . $challenge['delta'] . ');',
                'expected_positive_token' => $expectedPositive,
            ));
        }

        return array(
            array(
                'name' => 'shell_plain_echo_marker',
                'positive_payload' => 'echo ' . $expectedPositive,
                'negative_payload' => 'echo ' . self::MARKER_PREFIX . (string) ($challenge['negative_number'] + $challenge['delta']),
                'expected_positive_token' => $expectedPositive,
            ),
            array(
                'name' => 'shell_plain_printf_marker',
                'positive_payload' => 'printf ' . $expectedPositive,
                'negative_payload' => 'printf ' . self::MARKER_PREFIX . (string) ($challenge['negative_number'] + $challenge['delta']),
                'expected_positive_token' => $expectedPositive,
            ),
            array(
                'name' => 'shell_expr_marker',
                'positive_payload' => 'printf ' . self::MARKER_PREFIX . ';expr ' . $challenge['positive_number'] . ' + ' . $challenge['delta'],
                'negative_payload' => 'printf ' . self::MARKER_PREFIX . ';expr ' . $challenge['negative_number'] . ' + ' . $challenge['delta'],
                'expected_positive_token' => $expectedPositive,
            ),
            array(
                'name' => 'shell_arithmetic_expansion',
                'positive_payload' => 'printf ' . self::MARKER_PREFIX . '%s $(( ' . $challenge['positive_number'] . '+' . $challenge['delta'] . ' ))',
                'negative_payload' => 'printf ' . self::MARKER_PREFIX . '%s $(( ' . $challenge['negative_number'] . '+' . $challenge['delta'] . ' ))',
                'expected_positive_token' => $expectedPositive,
            ),
        );
    }

    private function usesEvalStylePayloads(VerificationJob $job, string $requestUri): bool
    {
        if (str_contains($requestUri, '/rce_eval')) {
            return true;
        }

        $candidateSnapshot = $job->candidateSnapshot();
        $sinkName = strtolower(trim((string) ($candidateSnapshot['sink_name'] ?? '')));
        if ($sinkName === 'include_or_eval') {
            return true;
        }

        $params = RequestParamPolicy::parseRequestUriQueryParams($requestUri);
        if ($params === array()) {
            return false;
        }

        $sinkParam = strtolower(trim((string) ($params['sink'] ?? '')));
        return in_array($sinkParam, array('eval', 'include_or_eval'), true);
    }
}
