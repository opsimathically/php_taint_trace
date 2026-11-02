<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Model;

final class DetectorCandidate
{
    /**
     * @param ReasonCode[] $reasonCodes
     * @param array<string, mixed> $metadata
     */
    public function __construct(
        private readonly string $id,
        private readonly string $sinkName,
        private readonly string $sinkCategory,
        array $reasonCodes,
        private readonly DetectorEvidence $detectorEvidence,
        private readonly TaintEvidence $taintEvidence,
        private readonly SinkEvidence $sinkEvidence,
        private readonly RequestEvidence $requestEvidence,
        private readonly EnvironmentEvidence $environmentEvidence,
        private readonly AuthorizationEvidence $authorizationEvidence,
        private readonly array $metadata = array()
    ) {
        usort(
            $reasonCodes,
            static fn (ReasonCode $left, ReasonCode $right): int => strcmp($left->value, $right->value)
        );
        $this->reasonCodes = array_values(array_unique($reasonCodes, SORT_REGULAR));
    }

    /**
     * @var ReasonCode[]
     */
    private readonly array $reasonCodes;

    public function id(): string
    {
        return $this->id;
    }

    public function sinkName(): string
    {
        return $this->sinkName;
    }

    public function sinkCategory(): string
    {
        return $this->sinkCategory;
    }

    /**
     * @return ReasonCode[]
     */
    public function reasonCodes(): array
    {
        return $this->reasonCodes;
    }

    public function detectorEvidence(): DetectorEvidence
    {
        return $this->detectorEvidence;
    }

    public function taintEvidence(): TaintEvidence
    {
        return $this->taintEvidence;
    }

    public function sinkEvidence(): SinkEvidence
    {
        return $this->sinkEvidence;
    }

    public function requestEvidence(): RequestEvidence
    {
        return $this->requestEvidence;
    }

    public function environmentEvidence(): EnvironmentEvidence
    {
        return $this->environmentEvidence;
    }

    public function authorizationEvidence(): AuthorizationEvidence
    {
        return $this->authorizationEvidence;
    }

    /**
     * @return array<string, mixed>
     */
    public function metadata(): array
    {
        return $this->metadata;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return array(
            'id' => $this->id,
            'sink_name' => $this->sinkName,
            'sink_category' => $this->sinkCategory,
            'reason_codes' => array_map(
                static fn (ReasonCode $reasonCode): string => $reasonCode->value,
                $this->reasonCodes
            ),
            'detector_evidence' => $this->detectorEvidence->toArray(),
            'taint_evidence' => $this->taintEvidence->toArray(),
            'sink_evidence' => $this->sinkEvidence->toArray(),
            'request_evidence' => $this->requestEvidence->toArray(),
            'environment_evidence' => $this->environmentEvidence->toArray(),
            'authorization_evidence' => $this->authorizationEvidence->toArray(),
            'metadata' => $this->metadata,
        );
    }
}
