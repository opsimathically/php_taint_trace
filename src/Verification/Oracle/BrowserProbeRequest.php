<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Oracle;

use PhpTaintTrace\Verification\Verifier\ReplayRequest;

final class BrowserProbeRequest
{
    public function __construct(
        private readonly string $url,
        private readonly string $nonce,
        private readonly int $timeoutMs,
        private readonly ReplayRequest $replayRequest
    ) {
    }

    public function url(): string
    {
        return $this->url;
    }

    public function nonce(): string
    {
        return $this->nonce;
    }

    public function timeoutMs(): int
    {
        return $this->timeoutMs;
    }

    public function replayRequest(): ReplayRequest
    {
        return $this->replayRequest;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return array(
            'url' => $this->url,
            'nonce' => $this->nonce,
            'timeout_ms' => $this->timeoutMs,
            'replay_request' => $this->replayRequest->toArray(),
        );
    }
}

