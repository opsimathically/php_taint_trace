<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Oracle;

use PhpTaintTrace\Verification\Model\VerificationJob;
use PhpTaintTrace\Verification\Model\VerificationOutcome;
use PhpTaintTrace\Verification\Verifier\ReplayRequest;

final class SsrfOracle implements OracleInterface
{
    public function supports(VerificationJob $job): bool
    {
        return $job->oracleType() === 'ssrf_oracle' || $job->sinkCategory() === 'ssrf';
    }

    public function verify(OracleContext $context): OracleDecision
    {
        $baseRequest = $this->baseRequest($context->job());
        if ($baseRequest === null) {
            return new OracleDecision(
                VerificationOutcome::INCONCLUSIVE,
                array('VERIFIER_SSRF_REQUEST_PARSE_FAILED'),
                'SSRF oracle could not parse replay request from candidate.',
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
                array('VERIFIER_SSRF_TARGET_PARAM_MISSING'),
                'SSRF oracle did not find a mutable parameter for replay.',
                array()
            );
        }

        $nonce = 'ptt_ssrf_nonce_' . bin2hex(random_bytes(4));
        $callbackBase = $context->replayRunner()->callbackBaseUrl();
        $positiveUrl = rtrim($callbackBase, '/') . '/?name=' . rawurlencode($nonce);
        $negativeUrl = rtrim($callbackBase, '/') . '/?name=ptt_ssrf_control';

        $rounds = array();
        $attempts = array();
        for ($round = 1; $round <= $context->verificationRounds(); $round++) {
            $labelSuffix = $round === 1 ? '' : '_repeat';
            $positive = ReplayPolicy::mutateRequest(
                $baseRequest,
                $target,
                $positiveUrl,
                'positive_callback' . $labelSuffix
            );
            $negative = ReplayPolicy::mutateRequest(
                $baseRequest,
                $target,
                $negativeUrl,
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

        $artifact = $context->writeArtifact('ssrf_oracle', array(
            'target_parameter' => $target['parameter'],
            'target_location' => $target['location'],
            'nonce' => $nonce,
            'callback_base' => $callbackBase,
            'rounds' => array_map(
                static fn (array $round): array => array(
                    'round' => $round['round'],
                    'positive' => $round['positive']->toArray(),
                    'negative' => $round['negative']->toArray(),
                ),
                $rounds
            ),
        ));

        foreach ($rounds as $round) {
            if (!$round['positive']->isSuccess() || !$round['negative']->isSuccess()) {
                return new OracleDecision(
                    VerificationOutcome::REPLAY_FAILED,
                    array('VERIFIER_SSRF_REPLAY_ERROR'),
                    'SSRF oracle replay failed for one or more attempts.',
                    $attempts,
                    array($artifact)
                );
            }
        }

        $roundSignals = array();
        $hasAmbiguousControlSignal = false;
        $hasNormalizationAmbiguity = false;
        foreach ($rounds as $round) {
            $positiveContainsNonce = str_contains($round['positive']->body(), $nonce);
            $negativeContainsNonce = str_contains($round['negative']->body(), $nonce);
            $roundSignals[] = $positiveContainsNonce && !$negativeContainsNonce;

            if ($positiveContainsNonce && $negativeContainsNonce) {
                $hasAmbiguousControlSignal = true;
            }

            if (
                (!$positiveContainsNonce && $this->containsNormalizedToken($round['positive']->body(), $nonce)) ||
                (!$negativeContainsNonce && $this->containsNormalizedToken($round['negative']->body(), $nonce))
            ) {
                $hasNormalizationAmbiguity = true;
            }
        }

        if ($this->hasSignalInstability($roundSignals)) {
            return new OracleDecision(
                VerificationOutcome::NOT_CONFIRMED,
                array('VERIFIER_SSRF_RESPONSE_INSTABILITY'),
                'SSRF oracle observed unstable callback differential across repeated replay attempts.',
                $attempts,
                array($artifact)
            );
        }

        if ($hasNormalizationAmbiguity) {
            return new OracleDecision(
                VerificationOutcome::NOT_CONFIRMED,
                array('VERIFIER_SSRF_NORMALIZATION_AMBIGUITY'),
                'SSRF oracle observed nonce indicators only after response normalization.',
                $attempts,
                array($artifact)
            );
        }

        if ($this->allTrue($roundSignals)) {
            return new OracleDecision(
                VerificationOutcome::CONFIRMED,
                array('VERIFIER_SSRF_CALLBACK_CONFIRMED'),
                'SSRF oracle observed stable callback nonce differential across repeated replay attempts.',
                $attempts,
                array($artifact)
            );
        }

        if ($hasAmbiguousControlSignal) {
            return new OracleDecision(
                VerificationOutcome::NOT_CONFIRMED,
                array('VERIFIER_SSRF_AMBIGUOUS_CONTROL_SIGNAL'),
                'SSRF oracle observed callback nonce in both positive and control replay responses.',
                $attempts,
                array($artifact)
            );
        }

        return new OracleDecision(
            VerificationOutcome::NOT_CONFIRMED,
            array('VERIFIER_SSRF_WEAK_DIFFERENTIAL', 'VERIFIER_SSRF_CONTROL_MISMATCH'),
            'SSRF oracle did not observe a strong, repeatable callback differential.',
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
}
