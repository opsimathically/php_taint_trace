<?php

declare(strict_types=1);

namespace PhpTaintTrace\Model;

final class Finding
{
    /**
     * @param array<string, mixed> $metadata
     */
    public function __construct(
        private readonly string $detector,
        private readonly string $severity,
        private readonly string $message,
        private readonly string $sinkName,
        private readonly SinkCategory $sinkCategory,
        private readonly array $metadata = array()
    ) {
    }

    public function detector(): string
    {
        return $this->detector;
    }

    public function severity(): string
    {
        return $this->severity;
    }

    public function message(): string
    {
        return $this->message;
    }

    public function sinkName(): string
    {
        return $this->sinkName;
    }

    public function sinkCategory(): SinkCategory
    {
        return $this->sinkCategory;
    }

    /**
     * @return array<string, mixed>
     */
    public function metadata(): array
    {
        return $this->metadata;
    }
}
