<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Oracle;

use PhpTaintTrace\Verification\Model\OracleArtifactRef;
use PhpTaintTrace\Verification\Model\VerificationOutcome;
use PhpTaintTrace\Verification\Verifier\ReplayResult;

final class OracleDecision
{
    /**
     * @param string[] $reasonCodes
     * @param ReplayResult[] $replayAttempts
     * @param OracleArtifactRef[] $artifacts
     * @param array<string, mixed> $metadata
     */
    public function __construct(
        private readonly VerificationOutcome $outcome,
        array $reasonCodes,
        private readonly string $summary,
        private readonly array $replayAttempts,
        private readonly array $artifacts = array(),
        private readonly array $metadata = array()
    ) {
        $reasonCodes = array_values(array_unique($reasonCodes));
        sort($reasonCodes);
        $this->reasonCodes = $reasonCodes;
    }

    /**
     * @var string[]
     */
    private readonly array $reasonCodes;

    public function outcome(): VerificationOutcome
    {
        return $this->outcome;
    }

    /**
     * @return string[]
     */
    public function reasonCodes(): array
    {
        return $this->reasonCodes;
    }

    public function summary(): string
    {
        return $this->summary;
    }

    /**
     * @return ReplayResult[]
     */
    public function replayAttempts(): array
    {
        return $this->replayAttempts;
    }

    /**
     * @return OracleArtifactRef[]
     */
    public function artifacts(): array
    {
        return $this->artifacts;
    }

    /**
     * @return array<string, mixed>
     */
    public function metadata(): array
    {
        return $this->metadata;
    }
}
