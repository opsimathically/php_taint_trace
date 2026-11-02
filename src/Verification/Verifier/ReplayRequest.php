<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Verifier;

final class ReplayRequest
{
    /**
     * @param array<string, string> $queryParams
     * @param array<string, string> $headers
     * @param array<string, string> $cookies
     * @param array<string, string> $bodyParams
     * @param array<string, mixed> $metadata
     */
    public function __construct(
        private readonly string $sinkCategory,
        private readonly string $method,
        private readonly string $path,
        private readonly array $queryParams,
        private readonly array $headers = array(),
        private readonly array $cookies = array(),
        private readonly array $bodyParams = array(),
        private readonly ?string $body = null,
        private readonly ?string $mutatedParameterLocation = null,
        private readonly ?string $mutatedParameter = null,
        private readonly ?string $payloadLabel = null,
        private readonly array $metadata = array()
    ) {
    }

    public function sinkCategory(): string
    {
        return $this->sinkCategory;
    }

    public function method(): string
    {
        return $this->method;
    }

    public function path(): string
    {
        return $this->path;
    }

    /**
     * @return array<string, string>
     */
    public function queryParams(): array
    {
        return $this->queryParams;
    }

    /**
     * @return array<string, string>
     */
    public function headers(): array
    {
        return $this->headers;
    }

    /**
     * @return array<string, string>
     */
    public function cookies(): array
    {
        return $this->cookies;
    }

    /**
     * @return array<string, string>
     */
    public function bodyParams(): array
    {
        return $this->bodyParams;
    }

    public function body(): ?string
    {
        return $this->body;
    }

    public function mutatedParameterLocation(): ?string
    {
        return $this->mutatedParameterLocation;
    }

    public function mutatedParameter(): ?string
    {
        return $this->mutatedParameter;
    }

    public function payloadLabel(): ?string
    {
        return $this->payloadLabel;
    }

    /**
     * @return array<string, mixed>
     */
    public function metadata(): array
    {
        return $this->metadata;
    }

    public function withMutatedQueryParameter(string $parameter, string $value, string $payloadLabel): self
    {
        $query = $this->queryParams;
        $query[$parameter] = $value;

        return new self(
            sinkCategory: $this->sinkCategory,
            method: $this->method,
            path: $this->path,
            queryParams: $query,
            headers: $this->headers,
            cookies: $this->cookies,
            bodyParams: $this->bodyParams,
            body: $this->body,
            mutatedParameterLocation: 'query',
            mutatedParameter: $parameter,
            payloadLabel: $payloadLabel,
            metadata: $this->metadata
        );
    }

    public function withMutatedBodyParameter(string $parameter, string $value, string $payloadLabel): self
    {
        if ($this->hasJsonBody()) {
            $bodyParams = self::parseBodyParams($this->body, $this->headers);
            $bodyParams[$parameter] = $value;
            $body = self::mutateJsonBody($this->body, $parameter, $value);
        } else {
            $bodyParams = $this->bodyParams;
            $bodyParams[$parameter] = $value;
            $body = http_build_query($bodyParams);
        }

        return new self(
            sinkCategory: $this->sinkCategory,
            method: $this->method,
            path: $this->path,
            queryParams: $this->queryParams,
            headers: $this->headers,
            cookies: $this->cookies,
            bodyParams: $bodyParams,
            body: $body,
            mutatedParameterLocation: 'body',
            mutatedParameter: $parameter,
            payloadLabel: $payloadLabel,
            metadata: $this->metadata
        );
    }

    public function withMutatedParameter(string $location, string $parameter, string $value, string $payloadLabel): self
    {
        return $location === 'body'
            ? $this->withMutatedBodyParameter($parameter, $value, $payloadLabel)
            : $this->withMutatedQueryParameter($parameter, $value, $payloadLabel);
    }

    /**
     * @param array<string, string> $headers
     * @param array<string, string> $cookies
     */
    public function withTransportContext(array $headers, array $cookies, ?string $body = null): self
    {
        $bodyParams = self::parseBodyParams($body, $headers);

        return new self(
            sinkCategory: $this->sinkCategory,
            method: $this->method,
            path: $this->path,
            queryParams: $this->queryParams,
            headers: $headers,
            cookies: $cookies,
            bodyParams: $bodyParams,
            body: $body ?? self::rebuildBodyFromParams($bodyParams),
            mutatedParameterLocation: $this->mutatedParameterLocation,
            mutatedParameter: $this->mutatedParameter,
            payloadLabel: $this->payloadLabel,
            metadata: $this->metadata
        );
    }

    public function relativeUri(): string
    {
        if ($this->queryParams === array()) {
            return $this->path;
        }

        return $this->path . '?' . http_build_query($this->queryParams);
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return array(
            'sink_category' => $this->sinkCategory,
            'method' => $this->method,
            'path' => $this->path,
            'query_params' => $this->queryParams,
            'headers' => $this->headers,
            'cookies' => $this->cookies,
            'body_params' => $this->bodyParams,
            'body' => $this->body,
            'mutated_parameter_location' => $this->mutatedParameterLocation,
            'mutated_parameter' => $this->mutatedParameter,
            'payload_label' => $this->payloadLabel,
            'metadata' => $this->metadata,
        );
    }

    /**
     * @param array<string, mixed> $payload
     */
    public static function fromArray(array $payload): self
    {
        $queryParams = array();
        if (is_array($payload['query_params'] ?? null)) {
            foreach ($payload['query_params'] as $key => $value) {
                $queryParams[(string) $key] = (string) $value;
            }
        }

        $headers = array();
        if (is_array($payload['headers'] ?? null)) {
            foreach ($payload['headers'] as $key => $value) {
                if (!is_scalar($value)) {
                    continue;
                }
                $normalizedKey = strtolower(trim((string) $key));
                if ($normalizedKey === '') {
                    continue;
                }
                $headers[$normalizedKey] = trim((string) $value);
            }
            ksort($headers);
        }

        $cookies = array();
        if (is_array($payload['cookies'] ?? null)) {
            foreach ($payload['cookies'] as $key => $value) {
                if (!is_scalar($value)) {
                    continue;
                }
                $normalizedKey = trim((string) $key);
                if ($normalizedKey === '') {
                    continue;
                }
                $cookies[$normalizedKey] = (string) $value;
            }
            ksort($cookies);
        }

        $body = isset($payload['body']) && is_scalar($payload['body']) ? (string) $payload['body'] : null;
        $bodyParams = array();
        if (is_array($payload['body_params'] ?? null)) {
            foreach ($payload['body_params'] as $key => $value) {
                if (!is_scalar($value)) {
                    continue;
                }
                $normalizedKey = trim((string) $key);
                if ($normalizedKey === '') {
                    continue;
                }
                $bodyParams[$normalizedKey] = (string) $value;
            }
            ksort($bodyParams);
        } else {
            $bodyParams = self::parseBodyParams($body, $headers);
        }

        if ($body === null && $bodyParams !== array()) {
            $body = self::rebuildBodyFromParams($bodyParams);
        }

        return new self(
            sinkCategory: (string) ($payload['sink_category'] ?? ''),
            method: strtoupper((string) ($payload['method'] ?? 'GET')),
            path: (string) ($payload['path'] ?? '/'),
            queryParams: $queryParams,
            headers: $headers,
            cookies: $cookies,
            bodyParams: $bodyParams,
            body: $body,
            mutatedParameterLocation: isset($payload['mutated_parameter_location'])
                ? (string) $payload['mutated_parameter_location']
                : null,
            mutatedParameter: isset($payload['mutated_parameter']) ? (string) $payload['mutated_parameter'] : null,
            payloadLabel: isset($payload['payload_label']) ? (string) $payload['payload_label'] : null,
            metadata: is_array($payload['metadata'] ?? null) ? $payload['metadata'] : array()
        );
    }

    public static function fromRequestUri(string $sinkCategory, string $method, string $requestUri): self
    {
        $path = parse_url($requestUri, PHP_URL_PATH);
        if (!is_string($path) || $path === '') {
            $path = '/';
        }

        $queryParams = array();
        $query = parse_url($requestUri, PHP_URL_QUERY);
        if (is_string($query)) {
            parse_str($query, $parsed);
            foreach ($parsed as $key => $value) {
                if (is_scalar($value)) {
                    $queryParams[(string) $key] = (string) $value;
                }
            }
        }

        return new self(
            sinkCategory: $sinkCategory,
            method: strtoupper($method),
            path: $path,
            queryParams: $queryParams
        );
    }

    /**
     * @param array<string, mixed> $replayPlan
     */
    public static function fromReplayPlan(string $sinkCategory, array $replayPlan): ?self
    {
        $requestUri = (string) ($replayPlan['request_uri'] ?? '');
        if ($requestUri === '') {
            return null;
        }

        $request = self::fromRequestUri(
            $sinkCategory,
            strtoupper((string) ($replayPlan['request_method'] ?? 'GET')),
            $requestUri
        );

        $headers = array();
        if (is_array($replayPlan['replay_headers'] ?? null)) {
            foreach ($replayPlan['replay_headers'] as $key => $value) {
                if (!is_scalar($value)) {
                    continue;
                }
                $normalized = strtolower(trim((string) $key));
                if ($normalized === '') {
                    continue;
                }
                $headers[$normalized] = trim((string) $value);
            }
            ksort($headers);
        }

        $cookies = array();
        if (is_array($replayPlan['replay_cookies'] ?? null)) {
            foreach ($replayPlan['replay_cookies'] as $key => $value) {
                if (!is_scalar($value)) {
                    continue;
                }
                $normalized = trim((string) $key);
                if ($normalized === '') {
                    continue;
                }
                $cookies[$normalized] = (string) $value;
            }
            ksort($cookies);
        }

        $body = null;
        if (isset($replayPlan['replay_body']) && is_scalar($replayPlan['replay_body'])) {
            $body = (string) $replayPlan['replay_body'];
        }

        return $request->withTransportContext($headers, $cookies, $body);
    }

    private function hasJsonBody(): bool
    {
        return self::headersIndicateJson($this->headers);
    }

    /**
     * @param array<string, string> $headers
     * @return array<string, string>
     */
    private static function parseBodyParams(?string $body, array $headers = array()): array
    {
        if (!is_string($body) || trim($body) === '') {
            return array();
        }

        if (self::headersIndicateJson($headers)) {
            $decoded = json_decode($body, true);
            if (!is_array($decoded)) {
                return array();
            }

            $params = array();
            self::flattenJsonScalarPaths($decoded, '', $params);
            ksort($params);
            return $params;
        }

        $parsed = array();
        parse_str($body, $parsed);
        if (!is_array($parsed)) {
            return array();
        }

        $params = array();
        foreach ($parsed as $key => $value) {
            if (!is_scalar($value)) {
                continue;
            }
            $normalizedKey = trim((string) $key);
            if ($normalizedKey === '') {
                continue;
            }
            $params[$normalizedKey] = (string) $value;
        }
        ksort($params);
        return $params;
    }

    /**
     * @param array<string, string> $headers
     */
    private static function headersIndicateJson(array $headers): bool
    {
        $contentType = strtolower(trim((string) ($headers['content-type'] ?? '')));
        return $contentType !== '' && str_contains($contentType, 'application/json');
    }

    /**
     * @param array<string, mixed> $value
     * @param array<string, string> $params
     */
    private static function flattenJsonScalarPaths(array $value, string $prefix, array &$params): void
    {
        foreach ($value as $key => $inner) {
            $segment = trim((string) $key);
            if ($segment === '') {
                continue;
            }

            $path = $prefix === '' ? $segment : $prefix . '.' . $segment;
            if (is_array($inner)) {
                self::flattenJsonScalarPaths($inner, $path, $params);
                continue;
            }

            if (is_scalar($inner) || $inner === null) {
                $params[$path] = $inner === null ? '' : (string) $inner;
            }
        }
    }

    private static function mutateJsonBody(?string $body, string $parameter, string $value): string
    {
        $decoded = is_string($body) ? json_decode($body, true) : null;
        if (!is_array($decoded)) {
            $decoded = array();
        }

        $segments = array_values(array_filter(
            array_map('trim', explode('.', $parameter)),
            static fn (string $segment): bool => $segment !== ''
        ));
        if ($segments === array()) {
            $segments = array($parameter);
        }

        $cursor = &$decoded;
        $lastIndex = count($segments) - 1;
        foreach ($segments as $index => $segment) {
            if ($index === $lastIndex) {
                $cursor[$segment] = $value;
                break;
            }

            if (!isset($cursor[$segment]) || !is_array($cursor[$segment])) {
                $cursor[$segment] = array();
            }
            $cursor = &$cursor[$segment];
        }
        unset($cursor);

        $encoded = json_encode($decoded, JSON_UNESCAPED_SLASHES);
        return is_string($encoded) ? $encoded : '{}';
    }

    /**
     * @param array<string, string> $params
     */
    private static function rebuildBodyFromParams(array $params): ?string
    {
        if ($params === array()) {
            return null;
        }

        return http_build_query($params);
    }
}
