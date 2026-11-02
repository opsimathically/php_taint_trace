<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Detector;

use PhpTaintTrace\Core\TaintedValue;
use PhpTaintTrace\Model\Finding;
use PhpTaintTrace\Model\SinkInvocation;
use PhpTaintTrace\Verification\Model\AuthorizationEvidence;
use PhpTaintTrace\Verification\Model\DetectorCandidate;
use PhpTaintTrace\Verification\Model\DetectorEvidence;
use PhpTaintTrace\Verification\Model\EnvironmentEvidence;
use PhpTaintTrace\Verification\Model\RequestEvidence;
use PhpTaintTrace\Verification\Model\SinkEvidence;
use PhpTaintTrace\Verification\Model\TaintEvidence;

final class CandidateBuilder
{
    /**
     * @var string[]
     */
    private const REQUEST_HEADER_ALLOWLIST = array(
        'accept',
        'accept-language',
        'host',
        'origin',
        'referer',
        'content-type',
        'content-length',
        'user-agent',
        'x-forwarded-for',
        'x-forwarded-proto',
    );

    public function __construct(
        private readonly CandidateFingerprint $fingerprint = new CandidateFingerprint(),
        private readonly ReasonCodeEmitter $reasonCodeEmitter = new ReasonCodeEmitter(),
        private readonly SinkArgumentRoleResolver $sinkArgumentRoleResolver = new SinkArgumentRoleResolver(),
        private readonly AuthorizationEvidenceResolver $authorizationEvidenceResolver = new AuthorizationEvidenceResolver()
    ) {
    }

    /**
     * @param Finding[] $findings
     */
    public function build(
        SinkInvocation $invocation,
        array $findings,
        ?RequestEvidence $requestEvidence = null,
        ?EnvironmentEvidence $environmentEvidence = null,
        ?AuthorizationEvidence $authorizationEvidence = null
    ): DetectorCandidate {
        $resolvedRequestEvidence = $requestEvidence ?? $this->defaultRequestEvidence();
        $resolvedEnvironmentEvidence = $environmentEvidence ?? $this->defaultEnvironmentEvidence();
        $resolvedAuthorizationEvidence = $authorizationEvidence
            ?? $this->authorizationEvidenceResolver->resolve($resolvedRequestEvidence);

        $taintEvidence = $this->buildTaintEvidence($invocation);
        $sinkEvidence = $this->buildSinkEvidence($invocation);
        $detectorEvidence = $this->buildDetectorEvidence($findings);

        $reasonCodes = $this->reasonCodeEmitter->emit(
            $invocation,
            $findings,
            $taintEvidence,
            $sinkEvidence,
            $resolvedAuthorizationEvidence
        );

        $id = $this->fingerprint->generate(
            $invocation,
            $resolvedRequestEvidence,
            $taintEvidence,
            $sinkEvidence,
            $detectorEvidence,
            $reasonCodes
        );

        return new DetectorCandidate(
            id: $id,
            sinkName: $invocation->sinkName(),
            sinkCategory: $invocation->sinkCategory()->value,
            reasonCodes: $reasonCodes,
            detectorEvidence: $detectorEvidence,
            taintEvidence: $taintEvidence,
            sinkEvidence: $sinkEvidence,
            requestEvidence: $resolvedRequestEvidence,
            environmentEvidence: $resolvedEnvironmentEvidence,
            authorizationEvidence: $resolvedAuthorizationEvidence,
            metadata: array('schema_version' => 'phase_a_v1')
        );
    }

    private function defaultRequestEvidence(): RequestEvidence
    {
        $server = $this->normalizeSuperglobal($_SERVER ?? array());
        $cookies = $this->normalizeSuperglobal($_COOKIE ?? array());
        $post = $this->normalizeSuperglobal($_POST ?? array());

        $requestHeaders = $this->extractRequestHeaders($server);
        $cookieKeys = $this->extractCookieKeys($cookies);
        $requestBody = $this->extractRequestBody($server, $post, $requestHeaders);

        $metadata = array(
            'request_headers' => $requestHeaders,
            'cookie_keys' => $cookieKeys,
        );
        if (is_string($requestBody) && $requestBody !== '') {
            $metadata['request_body'] = $requestBody;
            $metadata['request_body_format'] = $this->requestBodyFormat($requestHeaders);
        }

        return new RequestEvidence(
            timestamp: gmdate('c'),
            sapi: PHP_SAPI,
            requestMethod: isset($server['REQUEST_METHOD']) ? (string) $server['REQUEST_METHOD'] : null,
            requestUri: isset($server['REQUEST_URI']) ? (string) $server['REQUEST_URI'] : null,
            metadata: $metadata
        );
    }

    private function defaultEnvironmentEvidence(): EnvironmentEvidence
    {
        $extensions = get_loaded_extensions();
        sort($extensions);

        return new EnvironmentEvidence(
            phpVersion: PHP_VERSION,
            sapi: PHP_SAPI,
            loadedExtensions: $extensions,
            metadata: array('xmark_loaded' => extension_loaded('xmark'))
        );
    }

    private function buildSinkEvidence(SinkInvocation $invocation): SinkEvidence
    {
        $metadata = $invocation->metadata();

        return new SinkEvidence(
            sinkName: $invocation->sinkName(),
            sinkCategory: $invocation->sinkCategory()->value,
            argumentCount: count($invocation->arguments()),
            argumentRoles: $this->sinkArgumentRoleResolver->resolve($invocation),
            metadata: is_array($metadata) ? $metadata : array()
        );
    }

    /**
     * @param Finding[] $findings
     */
    private function buildDetectorEvidence(array $findings): DetectorEvidence
    {
        $detectors = array();
        $severities = array();
        $messages = array();

        foreach ($findings as $finding) {
            $detectors[] = $finding->detector();
            $severities[] = $finding->severity();
            $messages[] = $finding->message();
        }

        return new DetectorEvidence(
            findingCount: count($findings),
            detectors: $detectors,
            severities: $severities,
            messages: $messages
        );
    }

    private function buildTaintEvidence(SinkInvocation $invocation): TaintEvidence
    {
        $taintedArgumentIndexes = array();
        $sourceFamilies = array();

        foreach ($invocation->arguments() as $index => $argument) {
            $argumentSources = array();
            if (!$this->collectTaintSources($argument, $argumentSources)) {
                continue;
            }

            $taintedArgumentIndexes[] = (int) $index;
            foreach ($argumentSources as $sourceFamily) {
                $sourceFamilies[] = $sourceFamily;
            }
        }

        $sourceFamilies = array_values(array_unique($sourceFamilies));
        sort($sourceFamilies);

        return new TaintEvidence(
            sourcePresent: count($taintedArgumentIndexes) > 0,
            taintedArgumentIndexes: $taintedArgumentIndexes,
            sourceFamilies: $sourceFamilies
        );
    }

    /**
     * @param string[] $sourceFamilies
     */
    private function collectTaintSources(mixed $value, array &$sourceFamilies): bool
    {
        if ($value instanceof TaintedValue) {
            if (!$value->isTainted()) {
                return false;
            }

            foreach ($value->metadata()->sources() as $source) {
                $sourceFamilies[] = $this->sourceFamily($source);
            }

            return true;
        }

        if (!is_array($value)) {
            return false;
        }

        $tainted = false;
        foreach ($value as $inner) {
            if ($this->collectTaintSources($inner, $sourceFamilies)) {
                $tainted = true;
            }
        }

        return $tainted;
    }

    private function sourceFamily(string $source): string
    {
        $source = trim($source);
        if ($source === '') {
            return 'unknown';
        }

        if (str_contains($source, '[')) {
            return explode('[', $source, 2)[0];
        }

        if (str_contains($source, '.')) {
            return explode('.', $source, 2)[0];
        }

        return $source;
    }

    /**
     * @return array<string, mixed>
     */
    private function normalizeSuperglobal(mixed $value): array
    {
        if (is_array($value)) {
            return $value;
        }

        return array();
    }

    /**
     * @param array<string, mixed> $server
     * @return array<string, string>
     */
    private function extractRequestHeaders(array $server): array
    {
        $headers = array();
        foreach ($server as $key => $value) {
            if (!is_scalar($value)) {
                continue;
            }

            $normalizedKey = strtoupper((string) $key);
            if (str_starts_with($normalizedKey, 'HTTP_')) {
                $headerName = strtolower(str_replace('_', '-', substr($normalizedKey, 5)));
            } elseif ($normalizedKey === 'CONTENT_TYPE') {
                $headerName = 'content-type';
            } elseif ($normalizedKey === 'CONTENT_LENGTH') {
                $headerName = 'content-length';
            } else {
                continue;
            }

            if (!in_array($headerName, self::REQUEST_HEADER_ALLOWLIST, true)) {
                continue;
            }

            $normalizedValue = trim((string) $value);
            if ($normalizedValue === '') {
                continue;
            }
            $headers[$headerName] = $normalizedValue;
        }

        ksort($headers);
        return $headers;
    }

    /**
     * @param array<string, mixed> $cookies
     * @return string[]
     */
    private function extractCookieKeys(array $cookies): array
    {
        $keys = array();
        foreach (array_keys($cookies) as $cookieKey) {
            $normalized = trim((string) $cookieKey);
            if ($normalized === '') {
                continue;
            }
            $keys[] = $normalized;
        }

        $keys = array_values(array_unique($keys));
        sort($keys);
        return $keys;
    }

    /**
     * @param array<string, mixed> $server
     * @param array<string, mixed> $post
     * @param array<string, string> $requestHeaders
     */
    private function extractRequestBody(array $server, array $post, array $requestHeaders): ?string
    {
        $method = strtoupper(trim((string) ($server['REQUEST_METHOD'] ?? '')));
        if (!in_array($method, array('POST', 'PUT', 'PATCH', 'DELETE'), true)) {
            return null;
        }

        if ($post !== array()) {
            $postFields = array();
            foreach ($post as $key => $value) {
                if (!is_scalar($value)) {
                    continue;
                }
                $normalizedKey = trim((string) $key);
                if ($normalizedKey === '') {
                    continue;
                }
                $postFields[$normalizedKey] = (string) $value;
            }

            if ($postFields !== array()) {
                return http_build_query($postFields);
            }
        }

        $contentType = strtolower(trim((string) ($requestHeaders['content-type'] ?? '')));
        if (
            $contentType !== ''
            && !str_contains($contentType, 'application/x-www-form-urlencoded')
            && !str_contains($contentType, 'application/json')
        ) {
            return null;
        }

        $raw = file_get_contents('php://input');
        if (!is_string($raw)) {
            return null;
        }

        $raw = trim($raw);
        if ($raw === '') {
            return null;
        }

        return strlen($raw) > 8192 ? substr($raw, 0, 8192) : $raw;
    }

    /**
     * @param array<string, string> $requestHeaders
     */
    private function requestBodyFormat(array $requestHeaders): string
    {
        $contentType = strtolower(trim((string) ($requestHeaders['content-type'] ?? '')));
        if ($contentType !== '' && str_contains($contentType, 'application/json')) {
            return 'json';
        }

        return 'form';
    }
}
