<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Oracle;

use PhpTaintTrace\Verification\Model\VerificationJob;
use PhpTaintTrace\Verification\Model\VerificationOutcome;
use PhpTaintTrace\Verification\Verifier\ReplayRequest;

final class XssOracle implements OracleInterface
{
    public function supports(VerificationJob $job): bool
    {
        return $job->oracleType() === 'xss_oracle' || $job->sinkCategory() === 'xss';
    }

    public function verify(OracleContext $context): OracleDecision
    {
        $baseRequest = $this->baseRequest($context->job());
        if ($baseRequest === null) {
            return new OracleDecision(
                VerificationOutcome::INCONCLUSIVE,
                array('VERIFIER_XSS_REQUEST_PARSE_FAILED'),
                'XSS oracle could not parse replay request from candidate.',
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
                array('VERIFIER_XSS_TARGET_PARAM_MISSING'),
                'XSS oracle did not find a mutable parameter for replay.',
                array()
            );
        }

        $nonce = 'ptt_xss_nonce_' . bin2hex(random_bytes(4));
        $positivePayload = '<script>' . $nonce . '</script>';

        $rounds = array();
        $attempts = array();
        for ($round = 1; $round <= $context->verificationRounds(); $round++) {
            $labelSuffix = $round === 1 ? '' : '_repeat';
            $positive = ReplayPolicy::mutateRequest(
                $baseRequest,
                $target,
                $positivePayload,
                'positive_script' . $labelSuffix
            );
            $negative = ReplayPolicy::mutateRequest(
                $baseRequest,
                $target,
                'ptt_xss_control',
                'negative_control' . $labelSuffix
            );

            $positiveResult = $context->replayRunner()->replay($positive);
            $negativeResult = $context->replayRunner()->replay($negative);
            $attempts[] = $positiveResult;
            $attempts[] = $negativeResult;

            $positiveBody = $positiveResult->body();
            $negativeBody = $negativeResult->body();
            $positiveContainsScriptContext = str_contains($positiveBody, $positivePayload);
            $negativeContainsNonce = str_contains($negativeBody, $nonce);
            $hasNormalizationAmbiguity = (
                (!$positiveContainsScriptContext && $this->containsNormalizedToken($positiveBody, $positivePayload)) ||
                (!$negativeContainsNonce && $this->containsNormalizedToken($negativeBody, $nonce))
            );

            $rounds[] = array(
                'round' => $round,
                'positive' => $positiveResult,
                'negative' => $negativeResult,
                'signal' => $positiveContainsScriptContext && !$negativeContainsNonce,
                'ambiguous_control' => $positiveContainsScriptContext && $negativeContainsNonce,
                'normalization_ambiguity' => $hasNormalizationAmbiguity,
            );
        }

        $artifact = $context->writeArtifact('xss_oracle', array(
            'target_parameter' => $target['parameter'],
            'target_location' => $target['location'],
            'nonce' => $nonce,
            'positive_payload' => $positivePayload,
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
                    array('VERIFIER_XSS_REPLAY_ERROR'),
                    'XSS oracle replay failed for one or more attempts.',
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
            return new OracleDecision(
                VerificationOutcome::NOT_CONFIRMED,
                array('VERIFIER_XSS_RESPONSE_INSTABILITY'),
                'XSS oracle observed unstable response-context differential across repeated replay attempts.',
                $attempts,
                array($artifact)
            );
        }

        foreach ($rounds as $round) {
            if ($round['normalization_ambiguity'] === true) {
                return new OracleDecision(
                    VerificationOutcome::NOT_CONFIRMED,
                    array('VERIFIER_XSS_NORMALIZATION_AMBIGUITY'),
                    'XSS oracle observed script context indicators only after response normalization.',
                    $attempts,
                    array($artifact)
                );
            }
        }

        if ($this->allTrue($signals)) {
            return new OracleDecision(
                VerificationOutcome::CONFIRMED,
                array('VERIFIER_XSS_CONTEXT_CONFIRMED'),
                'XSS oracle observed stable script-context differential across repeated replay attempts.',
                $attempts,
                array($artifact)
            );
        }

        foreach ($rounds as $round) {
            if ($round['ambiguous_control'] === true) {
                return new OracleDecision(
                    VerificationOutcome::NOT_CONFIRMED,
                    array('VERIFIER_XSS_AMBIGUOUS_CONTROL_SIGNAL'),
                    'XSS oracle observed nonce reflection in both positive and control replay responses.',
                    $attempts,
                    array($artifact)
                );
            }
        }

        return new OracleDecision(
            VerificationOutcome::NOT_CONFIRMED,
            array('VERIFIER_XSS_WEAK_DIFFERENTIAL', 'VERIFIER_XSS_CONTEXT_NOT_OBSERVED'),
            'XSS oracle did not observe a strong, repeatable response-context differential.',
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
