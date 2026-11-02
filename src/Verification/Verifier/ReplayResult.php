<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Verifier;

final class ReplayResult
{
    /**
     * @param array<string, mixed> $metadata
     */
    public function __construct(
        private readonly ReplayRequest $request,
        private readonly ?int $statusCode,
        private readonly string $body,
        private readonly ?string $error,
        private readonly string $startedAt,
        private readonly string $finishedAt,
        private readonly array $metadata = array()
    ) {
    }

    public function request(): ReplayRequest
    {
        return $this->request;
    }

    public function statusCode(): ?int
    {
        return $this->statusCode;
    }

    public function body(): string
    {
        return $this->body;
    }

    public function error(): ?string
    {
        return $this->error;
    }

    public function startedAt(): string
    {
        return $this->startedAt;
    }

    public function finishedAt(): string
    {
        return $this->finishedAt;
    }

    public function isSuccess(): bool
    {
        return $this->error === null && $this->statusCode !== null;
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
            'request' => $this->request->toArray(),
            'status_code' => $this->statusCode,
            'body' => $this->body,
            'error' => $this->error,
            'started_at' => $this->startedAt,
            'finished_at' => $this->finishedAt,
            'metadata' => $this->metadata,
        );
    }
}
