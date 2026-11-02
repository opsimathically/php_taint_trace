<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Oracle;

use PhpTaintTrace\Verification\Model\VerificationJob;
use PhpTaintTrace\Verification\Model\VerificationOutcome;
use PhpTaintTrace\Verification\Verifier\ReplayRequest;
use PhpTaintTrace\Verification\Verifier\ReplayResult;

final class IdorOracle implements OracleInterface
{
    public function supports(VerificationJob $job): bool
    {
        return $job->oracleType() === 'idor_oracle' || $job->sinkCategory() === 'idor';
    }

    public function verify(OracleContext $context): OracleDecision
    {
        $baseRequest = $this->baseRequest($context->job());
        if ($baseRequest === null) {
            return new OracleDecision(
                VerificationOutcome::INCONCLUSIVE,
                array('VERIFIER_IDOR_REQUEST_PARSE_FAILED'),
                'IDOR oracle could not parse replay request from candidate.',
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

        $plan = $context->job()->replayPlan();
        $resourceParam = (string) ($plan['idor_resource_param'] ?? 'resource_id');
        $actorParam = (string) ($plan['idor_actor_param'] ?? 'actor_id');
        $modeParam = (string) ($plan['idor_mode_param'] ?? 'mode');

        $query = $baseRequest->queryParams();
        if (!array_key_exists($resourceParam, $query)) {
            return new OracleDecision(
                VerificationOutcome::INCONCLUSIVE,
                array('VERIFIER_IDOR_RESOURCE_PARAM_MISSING'),
                'IDOR oracle did not find the resource parameter in replay request.',
                array()
            );
        }

        $resourceId = (string) $query[$resourceParam];
        $ownerActor = $this->ownerActor($resourceId, $plan);
        $nonOwnerActor = $this->nonOwnerActor($ownerActor, $resourceId, $plan);

        $attempts = array();
        $rounds = array();
        for ($round = 1; $round <= $context->verificationRounds(); $round++) {
            $labelSuffix = $round === 1 ? '' : '_repeat';
            $ownerSafe = $baseRequest
                ->withMutatedQueryParameter($actorParam, $ownerActor, 'owner_safe' . $labelSuffix)
                ->withMutatedQueryParameter($modeParam, 'safe', 'owner_safe_mode' . $labelSuffix);
            $nonOwnerSafe = $baseRequest
                ->withMutatedQueryParameter($actorParam, $nonOwnerActor, 'non_owner_safe' . $labelSuffix)
                ->withMutatedQueryParameter($modeParam, 'safe', 'non_owner_safe_mode' . $labelSuffix);
            $nonOwnerVuln = $baseRequest
                ->withMutatedQueryParameter($actorParam, $nonOwnerActor, 'non_owner_vuln' . $labelSuffix)
                ->withMutatedQueryParameter($modeParam, 'vuln', 'non_owner_vuln_mode' . $labelSuffix);

            $ownerResult = $context->replayRunner()->replay($ownerSafe);
            $safeResult = $context->replayRunner()->replay($nonOwnerSafe);
            $vulnResult = $context->replayRunner()->replay($nonOwnerVuln);
            $attempts[] = $ownerResult;
            $attempts[] = $safeResult;
            $attempts[] = $vulnResult;

            $ownerAllowed = $this->isAllowed($ownerResult);
            $safeDenied = $this->isDenied($safeResult);
            $vulnAllowed = $this->isAllowed($vulnResult);
            $safeAllowed = !$safeDenied;

            $rounds[] = array(
                'round' => $round,
                'owner' => $ownerResult,
                'safe' => $safeResult,
                'vuln' => $vulnResult,
                'signal' => $ownerAllowed && $safeDenied && $vulnAllowed,
                'ambiguous_control' => ($safeAllowed === $vulnAllowed) || !$ownerAllowed,
                'normalization_ambiguity' => $this->hasMixedAuthzMarkers($ownerResult)
                    || $this->hasMixedAuthzMarkers($safeResult)
                    || $this->hasMixedAuthzMarkers($vulnResult),
            );
        }

        $artifact = $context->writeArtifact('idor_oracle', array(
            'resource_param' => $resourceParam,
            'actor_param' => $actorParam,
            'mode_param' => $modeParam,
            'resource_id' => $resourceId,
            'owner_actor' => $ownerActor,
            'non_owner_actor' => $nonOwnerActor,
            'rounds' => array_map(
                static fn (array $round): array => array(
                    'round' => $round['round'],
                    'owner_safe' => $round['owner']->toArray(),
                    'non_owner_safe' => $round['safe']->toArray(),
                    'non_owner_vuln' => $round['vuln']->toArray(),
                ),
                $rounds
            ),
        ));

        foreach ($rounds as $round) {
            if (!$round['owner']->isSuccess() || !$round['safe']->isSuccess() || !$round['vuln']->isSuccess()) {
                return new OracleDecision(
                    VerificationOutcome::REPLAY_FAILED,
                    array('VERIFIER_IDOR_REPLAY_ERROR'),
                    'IDOR oracle replay failed for one or more attempts.',
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
                array('VERIFIER_IDOR_RESPONSE_INSTABILITY'),
                'IDOR oracle observed unstable authorization differential across repeated replay attempts.',
                $attempts,
                array($artifact)
            );
        }

        foreach ($rounds as $round) {
            if ($round['normalization_ambiguity'] === true) {
                return new OracleDecision(
                    VerificationOutcome::NOT_CONFIRMED,
                    array('VERIFIER_IDOR_NORMALIZATION_AMBIGUITY'),
                    'IDOR oracle observed mixed allow/deny indicators in replay responses.',
                    $attempts,
                    array($artifact)
                );
            }
        }

        if ($this->allTrue($signals)) {
            return new OracleDecision(
                VerificationOutcome::CONFIRMED,
                array('VERIFIER_IDOR_DIFFERENTIAL_CONFIRMED'),
                'IDOR oracle observed stable owner/non-owner authorization differential across repeated replay attempts.',
                $attempts,
                array($artifact)
            );
        }

        foreach ($rounds as $round) {
            if ($round['ambiguous_control'] === true) {
                return new OracleDecision(
                    VerificationOutcome::NOT_CONFIRMED,
                    array('VERIFIER_IDOR_AMBIGUOUS_CONTROL_SIGNAL'),
                    'IDOR oracle observed control behavior that does not cleanly distinguish safe and vulnerable access paths.',
                    $attempts,
                    array($artifact)
                );
            }
        }

        return new OracleDecision(
            VerificationOutcome::NOT_CONFIRMED,
            array('VERIFIER_IDOR_WEAK_DIFFERENTIAL', 'VERIFIER_IDOR_CONTROL_MISMATCH'),
            'IDOR oracle did not observe a strong, repeatable authorization differential.',
            $attempts,
            array($artifact)
        );
    }

    private function baseRequest(VerificationJob $job): ?ReplayRequest
    {
        return ReplayRequest::fromReplayPlan($job->sinkCategory(), $job->replayPlan());
    }

    /**
     * @param array<string, mixed> $plan
     */
    private function ownerActor(string $resourceId, array $plan): string
    {
        $planned = $plan['idor_owner_actor'] ?? null;
        if (is_scalar($planned) && (string) $planned !== '') {
            return (string) $planned;
        }

        if (preg_match('/^\d+$/', $resourceId)) {
            return (string) ((int) $resourceId + 1000);
        }

        return 'owner_' . $resourceId;
    }

    /**
     * @param array<string, mixed> $plan
     */
    private function nonOwnerActor(string $ownerActor, string $resourceId, array $plan): string
    {
        $planned = $plan['idor_non_owner_actor'] ?? null;
        if (is_scalar($planned) && (string) $planned !== '') {
            return (string) $planned;
        }

        if (preg_match('/^\d+$/', $ownerActor)) {
            return (string) ((int) $ownerActor + 1);
        }

        return 'attacker_' . $resourceId;
    }

    private function isAllowed(ReplayResult $result): bool
    {
        $status = $result->statusCode();
        if (!is_int($status) || $status >= 400) {
            return false;
        }

        $body = strtolower($result->body());
        return str_contains($body, 'resource:');
    }

    private function isDenied(ReplayResult $result): bool
    {
        $status = $result->statusCode();
        if (is_int($status) && $status >= 400) {
            return true;
        }

        return str_contains(strtolower($result->body()), 'forbidden');
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

    private function hasMixedAuthzMarkers(ReplayResult $result): bool
    {
        return $this->isAllowed($result) && $this->isDenied($result);
    }
}
