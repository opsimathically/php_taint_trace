<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Model;

final class EnvironmentEvidence
{
    /**
     * @param string[] $loadedExtensions
     * @param array<string, mixed> $metadata
     */
    public function __construct(
        private readonly string $phpVersion,
        private readonly string $sapi,
        private readonly array $loadedExtensions,
        private readonly array $metadata = array()
    ) {
    }

    public function phpVersion(): string
    {
        return $this->phpVersion;
    }

    public function sapi(): string
    {
        return $this->sapi;
    }

    /**
     * @return string[]
     */
    public function loadedExtensions(): array
    {
        return $this->loadedExtensions;
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
            'php_version' => $this->phpVersion,
            'sapi' => $this->sapi,
            'loaded_extensions' => $this->loadedExtensions,
            'metadata' => $this->metadata,
        );
    }
}
