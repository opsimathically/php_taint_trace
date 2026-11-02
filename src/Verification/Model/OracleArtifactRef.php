<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Model;

final class OracleArtifactRef
{
    /**
     * @param array<string, mixed> $metadata
     */
    public function __construct(
        private readonly string $type,
        private readonly string $path,
        private readonly array $metadata = array()
    ) {
    }

    public function type(): string
    {
        return $this->type;
    }

    public function path(): string
    {
        return $this->path;
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
            'type' => $this->type,
            'path' => $this->path,
            'metadata' => $this->metadata,
        );
    }

    /**
     * @param array<string, mixed> $payload
     */
    public static function fromArray(array $payload): self
    {
        return new self(
            type: (string) ($payload['type'] ?? 'unknown'),
            path: (string) ($payload['path'] ?? ''),
            metadata: is_array($payload['metadata'] ?? null) ? $payload['metadata'] : array()
        );
    }
}
