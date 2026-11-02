<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Model;

final class AuthorizationEvidence
{
    /**
     * @param array<string, mixed> $metadata
     */
    public function __construct(
        private readonly ?string $principalId,
        private readonly ?string $resourceId,
        private readonly ?string $operation,
        private readonly array $metadata = array()
    ) {
    }

    public function principalId(): ?string
    {
        return $this->principalId;
    }

    public function resourceId(): ?string
    {
        return $this->resourceId;
    }

    public function operation(): ?string
    {
        return $this->operation;
    }

    /**
     * @return array<string, mixed>
     */
    public function metadata(): array
    {
        return $this->metadata;
    }

    public function isUnavailable(): bool
    {
        return $this->principalId === null
            && $this->resourceId === null
            && $this->operation === null;
    }

    public function isPresent(): bool
    {
        return $this->principalId !== null
            && $this->resourceId !== null
            && $this->operation !== null;
    }

    public function isPartial(): bool
    {
        return !$this->isUnavailable() && !$this->isPresent();
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return array(
            'principal_id' => $this->principalId,
            'resource_id' => $this->resourceId,
            'operation' => $this->operation,
            'metadata' => $this->metadata,
        );
    }
}
