<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Verifier;

final class LocalReplayRunner implements ReplayRunnerInterface
{
    public function __construct(
        private readonly string $baseUrl,
        private readonly int $timeoutSeconds = 4,
        private readonly ?string $callbackBaseOverride = null
    ) {
    }

    public function replay(ReplayRequest $request): ReplayResult
    {
        $startedAt = gmdate('c');
        $url = rtrim($this->baseUrl, '/') . $request->relativeUri();
        $replayId = 'ptt_replay_' . bin2hex(random_bytes(8));

        $error = null;
        $responseHeaders = null;
        set_error_handler(static function (int $severity, string $message) use (&$error): bool {
            $error = $message;
            return true;
        });

        try {
            $headerLines = array();
            foreach ($request->headers() as $name => $value) {
                $headerName = trim((string) $name);
                if ($headerName === '') {
                    continue;
                }

                $headerLines[] = $headerName . ': ' . trim((string) $value);
            }

            if ($request->cookies() !== array()) {
                $cookiePairs = array();
                foreach ($request->cookies() as $cookieName => $cookieValue) {
                    $normalizedCookieName = trim((string) $cookieName);
                    if ($normalizedCookieName === '') {
                        continue;
                    }
                    $cookiePairs[] = rawurlencode($normalizedCookieName) . '=' . rawurlencode((string) $cookieValue);
                }
                if ($cookiePairs !== array()) {
                    $headerLines[] = 'Cookie: ' . implode('; ', $cookiePairs);
                }
            }

            $headerLines[] = 'X-Php-Taint-Trace-Replay: 1';
            $headerLines[] = 'X-Php-Taint-Trace-Replay-Id: ' . $replayId;
            if ($request->payloadLabel() !== null && trim($request->payloadLabel()) !== '') {
                $headerLines[] = 'X-Php-Taint-Trace-Replay-Label: ' . trim($request->payloadLabel());
            }
            if ($request->mutatedParameter() !== null && trim($request->mutatedParameter()) !== '') {
                $headerLines[] = 'X-Php-Taint-Trace-Replay-Mutated-Parameter: ' . trim($request->mutatedParameter());
            }
            if ($request->mutatedParameterLocation() !== null && trim($request->mutatedParameterLocation()) !== '') {
                $headerLines[] = 'X-Php-Taint-Trace-Replay-Mutated-Location: ' . trim($request->mutatedParameterLocation());
            }
            if (
                in_array(strtoupper($request->method()), array('POST', 'PUT', 'PATCH', 'DELETE'), true) &&
                $request->body() !== null &&
                !$this->hasHeader($headerLines, 'content-type')
            ) {
                $headerLines[] = 'Content-Type: application/x-www-form-urlencoded';
            }

            $context = stream_context_create(array(
                'http' => array(
                    'method' => $request->method(),
                    'ignore_errors' => true,
                    'timeout' => $this->timeoutSeconds,
                    'header' => implode("\r\n", $headerLines) . "\r\n",
                    'content' => $this->requestBody($request),
                ),
            ));
            $body = @file_get_contents($url, false, $context);
            $responseHeaders = $http_response_header ?? null;
        } finally {
            restore_error_handler();
        }

        if (!is_string($body)) {
            $body = '';
        }

        return new ReplayResult(
            request: $request,
            statusCode: self::extractStatusCode($responseHeaders),
            body: $body,
            error: $error,
            startedAt: $startedAt,
            finishedAt: gmdate('c'),
            metadata: array(
                'url' => $url,
                'replay_id' => $replayId,
                'payload_label' => $request->payloadLabel(),
                'mutated_parameter' => $request->mutatedParameter(),
                'mutated_parameter_location' => $request->mutatedParameterLocation(),
            )
        );
    }

    public function callbackBaseUrl(): string
    {
        if ($this->callbackBaseOverride !== null && trim($this->callbackBaseOverride) !== '') {
            return rtrim($this->callbackBaseOverride, '/');
        }

        return rtrim($this->baseUrl, '/');
    }

    /**
     * @param array<int, string>|null $headers
     */
    private static function extractStatusCode(?array $headers): ?int
    {
        if (!is_array($headers) || $headers === array()) {
            return null;
        }

        foreach ($headers as $line) {
            if (!preg_match('/^HTTP\/\d\.\d\s+(\d+)/', $line, $matches)) {
                continue;
            }

            return (int) $matches[1];
        }

        return null;
    }

    /**
     * @param string[] $headerLines
     */
    private function hasHeader(array $headerLines, string $headerName): bool
    {
        $needle = strtolower(trim($headerName));
        foreach ($headerLines as $line) {
            if (!is_string($line)) {
                continue;
            }
            $parts = explode(':', $line, 2);
            $name = strtolower(trim((string) ($parts[0] ?? '')));
            if ($name === $needle) {
                return true;
            }
        }

        return false;
    }

    private function requestBody(ReplayRequest $request): string
    {
        $body = $request->body();
        if ($body !== null) {
            return $body;
        }

        if ($request->bodyParams() !== array()) {
            return http_build_query($request->bodyParams());
        }

        return '';
    }
}
