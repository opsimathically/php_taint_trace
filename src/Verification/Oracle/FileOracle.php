<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Oracle;

use PhpTaintTrace\Verification\Model\VerificationJob;
use PhpTaintTrace\Verification\Model\VerificationOutcome;
use PhpTaintTrace\Verification\Verifier\ReplayRequest;
use PhpTaintTrace\Verification\Verifier\ReplayResult;

final class FileOracle implements OracleInterface
{
    public function supports(VerificationJob $job): bool
    {
        return $job->oracleType() === 'file_oracle' || $job->sinkCategory() === 'file';
    }

    public function verify(OracleContext $context): OracleDecision
    {
        $baseRequest = $this->baseRequest($context->job());
        if ($baseRequest === null) {
            return new OracleDecision(
                VerificationOutcome::INCONCLUSIVE,
                array('VERIFIER_FILE_REQUEST_PARSE_FAILED'),
                'File oracle could not parse replay request from candidate.',
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
                array('VERIFIER_FILE_TARGET_PARAM_MISSING'),
                'File oracle did not find a mutable parameter for replay.',
                array()
            );
        }

        $positivePath = '/etc/hostname';
        $negativePath = '/definitely_missing_ptt_file_control';
        $rounds = array();
        $attempts = array();
        for ($round = 1; $round <= $context->verificationRounds(); $round++) {
            $labelSuffix = $round === 1 ? '' : '_repeat';
            $positive = ReplayPolicy::mutateRequest(
                $baseRequest,
                $target,
                $positivePath,
                'positive_file_read' . $labelSuffix
            );
            $negative = ReplayPolicy::mutateRequest(
                $baseRequest,
                $target,
                $negativePath,
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
                'signal' => $this->isReadableSuccess($positiveResult) && $this->isDeniedFailure($negativeResult),
                'ambiguous_control' => $this->isControlAmbiguity($positiveResult, $negativeResult),
                'normalization_ambiguity' => $this->isNormalizationAmbiguity($positiveResult, $negativeResult),
            );
        }

        $artifact = $context->writeArtifact('file_oracle', array(
            'target_parameter' => $target['parameter'],
            'target_location' => $target['location'],
            'positive_path' => $positivePath,
            'negative_path' => $negativePath,
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
                    array('VERIFIER_FILE_REPLAY_ERROR'),
                    'File oracle replay failed for one or more attempts.',
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
                array('VERIFIER_FILE_RESPONSE_INSTABILITY'),
                'File oracle observed unstable differential across repeated replay attempts.',
                $attempts,
                array($artifact)
            );
        }

        foreach ($rounds as $round) {
            if ($round['normalization_ambiguity'] === true) {
                return new OracleDecision(
                    VerificationOutcome::NOT_CONFIRMED,
                    array('VERIFIER_FILE_NORMALIZATION_AMBIGUITY'),
                    'File oracle observed mixed success/deny indicators in replay responses.',
                    $attempts,
                    array($artifact)
                );
            }
        }

        if ($this->allTrue($signals)) {
            return new OracleDecision(
                VerificationOutcome::CONFIRMED,
                array('VERIFIER_FILE_DIFFERENTIAL_CONFIRMED'),
                'File oracle observed stable read-success/deny differential across repeated replay attempts.',
                $attempts,
                array($artifact)
            );
        }

        foreach ($rounds as $round) {
            if ($round['ambiguous_control'] === true) {
                return new OracleDecision(
                    VerificationOutcome::NOT_CONFIRMED,
                    array('VERIFIER_FILE_AMBIGUOUS_CONTROL_SIGNAL'),
                    'File oracle observed control responses that do not cleanly separate positive and negative behavior.',
                    $attempts,
                    array($artifact)
                );
            }
        }

        return new OracleDecision(
            VerificationOutcome::NOT_CONFIRMED,
            array('VERIFIER_FILE_WEAK_DIFFERENTIAL', 'VERIFIER_FILE_CONTROL_MISMATCH'),
            'File oracle did not observe a strong, repeatable success/deny differential.',
            $attempts,
            array($artifact)
        );
    }

    private function baseRequest(VerificationJob $job): ?ReplayRequest
    {
        return ReplayRequest::fromReplayPlan($job->sinkCategory(), $job->replayPlan());
    }

    private function isReadableSuccess(ReplayResult $result): bool
    {
        $status = $result->statusCode();
        if (!is_int($status) || $status >= 400) {
            return false;
        }

        return trim($result->body()) !== '' && !str_contains(strtolower($result->body()), 'read failed');
    }

    private function isDeniedFailure(ReplayResult $result): bool
    {
        $status = $result->statusCode();
        if (is_int($status) && $status >= 400) {
            return true;
        }

        return str_contains(strtolower($result->body()), 'read failed');
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

    private function isControlAmbiguity(ReplayResult $positive, ReplayResult $negative): bool
    {
        $positiveReadable = $this->isReadableSuccess($positive);
        $negativeDenied = $this->isDeniedFailure($negative);

        return ($positiveReadable && !$negativeDenied) || (!$positiveReadable && $negativeDenied);
    }

    private function isNormalizationAmbiguity(ReplayResult $positive, ReplayResult $negative): bool
    {
        return $this->hasMixedAllowDenyMarkers($positive) || $this->hasMixedAllowDenyMarkers($negative);
    }

    private function hasMixedAllowDenyMarkers(ReplayResult $result): bool
    {
        $body = strtolower($result->body());
        $hasAllowMarker = str_contains($body, 'fixture-host') || str_contains($body, 'allowed-file');
        $hasDenyMarker = str_contains($body, 'read failed') || str_contains($body, 'forbidden');

        return $hasAllowMarker && $hasDenyMarker;
    }
}
