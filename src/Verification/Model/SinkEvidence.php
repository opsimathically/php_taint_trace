<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Model;

final class SinkEvidence
{
    /**
     * @param array<int, string> $argumentRoles
     * @param array<string, mixed> $metadata
     */
    public function __construct(
        private readonly string $sinkName,
        private readonly string $sinkCategory,
        private readonly int $argumentCount,
        private readonly array $argumentRoles,
        private readonly array $metadata = array()
    ) {
    }

    public function sinkName(): string
    {
        return $this->sinkName;
    }

    public function sinkCategory(): string
    {
        return $this->sinkCategory;
    }

    public function argumentCount(): int
    {
        return $this->argumentCount;
    }

    /**
     * @return array<int, string>
     */
    public function argumentRoles(): array
    {
        return $this->argumentRoles;
    }

    public function hasPrimaryRole(): bool
    {
        foreach ($this->argumentRoles as $role) {
            if ($role === 'primary') {
                return true;
            }
        }

        return false;
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
            'sink_name' => $this->sinkName,
            'sink_category' => $this->sinkCategory,
            'argument_count' => $this->argumentCount,
            'argument_roles' => $this->argumentRoles,
            'metadata' => $this->metadata,
        );
    }
}
