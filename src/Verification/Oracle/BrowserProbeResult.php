<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Oracle;

final class BrowserProbeResult
{
    /**
     * @param array<string, mixed> $metadata
     */
    public function __construct(
        private readonly bool $success,
        private readonly bool $executionObserved,
        private readonly ?string $error,
        private readonly ?int $exitCode,
        private readonly string $stdout,
        private readonly string $stderr,
        private readonly array $metadata = array()
    ) {
    }

    public function success(): bool
    {
        return $this->success;
    }

    public function executionObserved(): bool
    {
        return $this->executionObserved;
    }

    public function error(): ?string
    {
        return $this->error;
    }

    public function exitCode(): ?int
    {
        return $this->exitCode;
    }

    public function stdout(): string
    {
        return $this->stdout;
    }

    public function stderr(): string
    {
        return $this->stderr;
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
            'success' => $this->success,
            'execution_observed' => $this->executionObserved,
            'error' => $this->error,
            'exit_code' => $this->exitCode,
            'stdout' => $this->stdout,
            'stderr' => $this->stderr,
            'metadata' => $this->metadata,
        );
    }
}

