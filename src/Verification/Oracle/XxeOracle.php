<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Oracle;

use PhpTaintTrace\Verification\Model\VerificationJob;
use PhpTaintTrace\Verification\Model\VerificationOutcome;
use PhpTaintTrace\Verification\Verifier\ReplayRequest;

final class XxeOracle implements OracleInterface
{
    public function supports(VerificationJob $job): bool
    {
        return $job->oracleType() === 'xxe_oracle' || $job->sinkCategory() === 'xxe';
    }

    public function verify(OracleContext $context): OracleDecision
    {
        $baseRequest = $this->baseRequest($context->job());
        if ($baseRequest === null) {
            return new OracleDecision(
                VerificationOutcome::INCONCLUSIVE,
                array('VERIFIER_XXE_REQUEST_PARSE_FAILED'),
                'XXE oracle could not parse replay request from candidate.',
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
                array('VERIFIER_XXE_TARGET_PARAM_MISSING'),
                'XXE oracle did not find a mutable parameter for replay.',
                array()
            );
        }

        $nonce = 'ptt_xxe_nonce_' . bin2hex(random_bytes(4));
        $positivePayload = $this->positivePayload($context->replayRunner()->callbackBaseUrl(), $nonce);
        $negativePayload = '<?xml version="1.0"?><root>ptt_xxe_control</root>';

        $rounds = array();
        $attempts = array();
        for ($round = 1; $round <= $context->verificationRounds(); $round++) {
            $labelSuffix = $round === 1 ? '' : '_repeat';
            $positive = ReplayPolicy::mutateRequest(
                $baseRequest,
                $target,
                $positivePayload,
                'positive_entity' . $labelSuffix
            );
            $negative = ReplayPolicy::mutateRequest(
                $baseRequest,
                $target,
                $negativePayload,
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

        $artifact = $context->writeArtifact('xxe_oracle', array(
            'target_parameter' => $target['parameter'],
            'target_location' => $target['location'],
            'nonce' => $nonce,
            'positive_payload' => $positivePayload,
            'negative_payload' => $negativePayload,
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
                    array('VERIFIER_XXE_REPLAY_ERROR'),
                    'XXE oracle replay failed for one or more attempts.',
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
                array('VERIFIER_XXE_RESPONSE_INSTABILITY'),
                'XXE oracle observed unstable differential across repeated replay attempts.',
                $attempts,
                array($artifact)
            );
        }

        if ($hasNormalizationAmbiguity) {
            return new OracleDecision(
                VerificationOutcome::NOT_CONFIRMED,
                array('VERIFIER_XXE_NORMALIZATION_AMBIGUITY'),
                'XXE oracle observed nonce indicators only after response normalization.',
                $attempts,
                array($artifact)
            );
        }

        if ($this->allTrue($roundSignals)) {
            return new OracleDecision(
                VerificationOutcome::CONFIRMED,
                array('VERIFIER_XXE_ENTITY_RESOLUTION_CONFIRMED'),
                'XXE oracle observed stable external-entity nonce differential across repeated replay attempts.',
                $attempts,
                array($artifact)
            );
        }

        if ($hasAmbiguousControlSignal) {
            return new OracleDecision(
                VerificationOutcome::NOT_CONFIRMED,
                array('VERIFIER_XXE_AMBIGUOUS_CONTROL_SIGNAL'),
                'XXE oracle observed nonce in both positive and control replay responses.',
                $attempts,
                array($artifact)
            );
        }

        return new OracleDecision(
            VerificationOutcome::NOT_CONFIRMED,
            array('VERIFIER_XXE_WEAK_DIFFERENTIAL', 'VERIFIER_XXE_CONTROL_MISMATCH'),
            'XXE oracle did not observe a strong, repeatable external-entity differential.',
            $attempts,
            array($artifact)
        );
    }

    private function baseRequest(VerificationJob $job): ?ReplayRequest
    {
        return ReplayRequest::fromReplayPlan($job->sinkCategory(), $job->replayPlan());
    }

    private function positivePayload(string $callbackBaseUrl, string $nonce): string
    {
        $callbackUrl = rtrim($callbackBaseUrl, '/') . '/?name=' . rawurlencode($nonce);
        return sprintf(
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "%s">]><root>&xxe;</root>',
            $callbackUrl
        );
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
