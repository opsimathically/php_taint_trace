<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Model;

final class RequestEvidence
{
    /**
     * @param array<string, mixed> $metadata
     */
    public function __construct(
        private readonly string $timestamp,
        private readonly string $sapi,
        private readonly ?string $requestMethod,
        private readonly ?string $requestUri,
        private readonly array $metadata = array()
    ) {
    }

    public function timestamp(): string
    {
        return $this->timestamp;
    }

    public function sapi(): string
    {
        return $this->sapi;
    }

    public function requestMethod(): ?string
    {
        return $this->requestMethod;
    }

    public function requestUri(): ?string
    {
        return $this->requestUri;
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
            'timestamp' => $this->timestamp,
            'sapi' => $this->sapi,
            'request_method' => $this->requestMethod,
            'request_uri' => $this->requestUri,
            'metadata' => $this->metadata,
        );
    }
}
