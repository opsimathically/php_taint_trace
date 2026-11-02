<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Oracle;

use PhpTaintTrace\Verification\Model\VerificationJob;
use PhpTaintTrace\Verification\Model\VerificationOutcome;
use PhpTaintTrace\Verification\Verifier\ReplayRequest;

final class BrowserAwareXssOracle implements OracleInterface
{
    public function __construct(
        private readonly OracleInterface $fallbackOracle,
        private readonly ?BrowserProbeRunnerInterface $browserProbeRunner = null,
        private readonly bool $enforceBrowserExecution = false,
        private readonly int $probeTimeoutMs = 10000
    ) {
    }

    public function supports(VerificationJob $job): bool
    {
        return $this->fallbackOracle->supports($job);
    }

    public function verify(OracleContext $context): OracleDecision
    {
        $fallbackDecision = $this->fallbackOracle->verify($context);
        if ($fallbackDecision->outcome() !== VerificationOutcome::CONFIRMED) {
            return $fallbackDecision;
        }

        if ($this->browserProbeRunner === null) {
            return $this->augmentDecision(
                $fallbackDecision,
                array('VERIFIER_XSS_BROWSER_PROBE_UNCONFIGURED'),
                array('mode' => 'fallback_only')
            );
        }

        $baseRequest = ReplayRequest::fromReplayPlan(
            $context->job()->sinkCategory(),
            $context->job()->replayPlan()
        );
        if ($baseRequest === null) {
            return $this->probeCapabilityFailure(
                $fallbackDecision,
                'VERIFIER_XSS_BROWSER_REQUEST_PARSE_FAILED',
                'XSS browser probe could not parse replay request from candidate.'
            );
        }

        $policyFailure = ReplayPolicy::enforceMethodPolicy(
            $context->job(),
            $baseRequest,
            array('GET'),
            'VERIFIER_XSS_BROWSER_METHOD_BLOCKED',
            'XSS browser probe supports GET requests only.'
        );
        if ($policyFailure !== null) {
            return $this->probeCapabilityFailure(
                $fallbackDecision,
                'VERIFIER_XSS_BROWSER_METHOD_BLOCKED',
                'XSS browser probe supports GET requests only.'
            );
        }

        $target = ReplayPolicy::resolveTargetParameter($context->job(), $baseRequest);
        if ($target === null) {
            return $this->probeCapabilityFailure(
                $fallbackDecision,
                'VERIFIER_XSS_BROWSER_TARGET_PARAM_MISSING',
                'XSS browser probe did not find a mutable parameter for replay.'
            );
        }

        $nonce = 'ptt_xss_browser_nonce_' . bin2hex(random_bytes(4));
        $payload = '<script>window.__ptt_xss_nonce="' . $nonce . '";document.documentElement.setAttribute("data-ptt-xss","' . $nonce . '");</script>';
        $probeReplay = ReplayPolicy::mutateRequest(
            $baseRequest,
            $target,
            $payload,
            'browser_probe'
        );
        $probeRequest = new BrowserProbeRequest(
            $this->probeUrl($context, $probeReplay),
            $nonce,
            max(1000, $this->probeTimeoutMs),
            $probeReplay
        );

        $probeResult = $this->browserProbeRunner->probe($probeRequest);
        $probeArtifact = $context->writeArtifact('xss_browser_probe', array(
            'request' => $probeRequest->toArray(),
            'target_parameter' => $target['parameter'],
            'target_location' => $target['location'],
            'result' => $probeResult->toArray(),
        ));

        if (!$probeResult->success()) {
            return $this->probeExecutionFailure(
                $fallbackDecision,
                array('VERIFIER_XSS_BROWSER_PROBE_FAILED'),
                'XSS browser probe failed to execute successfully.',
                array($probeArtifact),
                $probeResult
            );
        }

        if ($probeResult->executionObserved()) {
            return $this->augmentDecision(
                $fallbackDecision,
                array('VERIFIER_XSS_BROWSER_EXECUTION_CONFIRMED'),
                array(
                    'probe' => $probeResult->toArray(),
                    'enforced' => $this->enforceBrowserExecution,
                ),
                array($probeArtifact)
            );
        }

        return $this->probeExecutionFailure(
            $fallbackDecision,
            array('VERIFIER_XSS_BROWSER_EXECUTION_NOT_OBSERVED'),
            'XSS browser probe did not observe JavaScript execution for the replayed payload.',
            array($probeArtifact),
            $probeResult
        );
    }

    /**
     * @param string[] $reasonCodes
     * @param array<string, mixed> $metadata
     * @param \PhpTaintTrace\Verification\Model\OracleArtifactRef[] $artifacts
     */
    private function augmentDecision(
        OracleDecision $base,
        array $reasonCodes,
        array $metadata = array(),
        array $artifacts = array()
    ): OracleDecision {
        return new OracleDecision(
            outcome: $base->outcome(),
            reasonCodes: array_merge($base->reasonCodes(), $reasonCodes),
            summary: $base->summary(),
            replayAttempts: $base->replayAttempts(),
            artifacts: array_merge($base->artifacts(), $artifacts),
            metadata: array_merge($base->metadata(), $metadata)
        );
    }

    private function probeCapabilityFailure(
        OracleDecision $fallbackDecision,
        string $reasonCode,
        string $message
    ): OracleDecision {
        if ($this->enforceBrowserExecution) {
            return new OracleDecision(
                VerificationOutcome::NOT_CONFIRMED,
                array($reasonCode),
                $message,
                $fallbackDecision->replayAttempts(),
                $fallbackDecision->artifacts(),
                array_merge(
                    $fallbackDecision->metadata(),
                    array('browser_probe' => 'required_but_unavailable')
                )
            );
        }

        return $this->augmentDecision(
            $fallbackDecision,
            array($reasonCode, 'VERIFIER_XSS_BROWSER_ADVISORY_ONLY'),
            array('browser_probe' => 'advisory_unavailable')
        );
    }

    /**
     * @param string[] $reasonCodes
     * @param \PhpTaintTrace\Verification\Model\OracleArtifactRef[] $artifacts
     */
    private function probeExecutionFailure(
        OracleDecision $fallbackDecision,
        array $reasonCodes,
        string $message,
        array $artifacts,
        BrowserProbeResult $probeResult
    ): OracleDecision {
        if ($this->enforceBrowserExecution) {
            return new OracleDecision(
                VerificationOutcome::NOT_CONFIRMED,
                $reasonCodes,
                $message,
                $fallbackDecision->replayAttempts(),
                array_merge($fallbackDecision->artifacts(), $artifacts),
                array_merge(
                    $fallbackDecision->metadata(),
                    array('browser_probe' => $probeResult->toArray(), 'enforced' => true)
                )
            );
        }

        return $this->augmentDecision(
            $fallbackDecision,
            array_merge($reasonCodes, array('VERIFIER_XSS_BROWSER_ADVISORY_ONLY')),
            array('browser_probe' => $probeResult->toArray(), 'enforced' => false),
            $artifacts
        );
    }

    private function probeUrl(OracleContext $context, ReplayRequest $request): string
    {
        $base = rtrim($context->replayRunner()->callbackBaseUrl(), '/');
        $relative = $request->relativeUri();
        if (str_starts_with($relative, 'http://') || str_starts_with($relative, 'https://')) {
            return $relative;
        }

        return $base . '/' . ltrim($relative, '/');
    }
}

