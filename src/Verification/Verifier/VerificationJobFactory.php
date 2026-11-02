<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Verifier;

use PhpTaintTrace\Verification\Model\DetectorCandidate;
use PhpTaintTrace\Verification\Model\VerificationJob;

final class VerificationJobFactory
{
    public function __construct(
        private readonly string $replayProfile
    ) {
    }

    public function createFromCandidate(DetectorCandidate $candidate): ?VerificationJob
    {
        $candidateCategory = $candidate->sinkCategory();
        if (!in_array($candidateCategory, array('rce', 'ssrf', 'sqli', 'file', 'xss', 'idor', 'xxe'), true)) {
            return null;
        }

        if ($candidate->detectorEvidence()->findingCount() < 1) {
            return null;
        }

        $candidateSnapshot = $candidate->toArray();
        $requestEvidence = $candidateSnapshot['request_evidence'] ?? array();
        $requestMethod = (string) ($requestEvidence['request_method'] ?? 'GET');
        $requestUri = (string) ($requestEvidence['request_uri'] ?? '/');
        $requestQueryParams = RequestParamPolicy::parseRequestUriQueryParams($requestUri);
        $normalizedRequestMethod = strtoupper($requestMethod);

        $resolved = $this->resolveTargetCategoryAndOracle($candidateCategory, $requestQueryParams);
        if ($resolved === null) {
            return null;
        }

        $sinkCategory = $resolved['sink_category'];
        $oracleType = $resolved['oracle_type'];
        $jobId = hash('sha256', implode('|', array(
            $candidate->id(),
            $oracleType,
            $this->replayProfile,
        )));

        $transportContext = $this->transportContextFromCandidate($candidateSnapshot);
        $targetPlan = $this->targetMutationPlan(
            $sinkCategory,
            $normalizedRequestMethod,
            $requestQueryParams,
            $transportContext['headers'],
            $transportContext['body']
        );

        $replayPlan = array(
            'request_method' => $normalizedRequestMethod,
            'request_uri' => $requestUri,
            'target_query_param' => $targetPlan['target_query_param'],
            'target_param_location' => $targetPlan['target_param_location'],
            'allowed_methods' => array($normalizedRequestMethod),
        );
        if (is_string($targetPlan['target_body_param'])) {
            $replayPlan['target_body_param'] = $targetPlan['target_body_param'];
        }
        if (is_string($targetPlan['target_body_format'])) {
            $replayPlan['target_body_format'] = $targetPlan['target_body_format'];
        }
        if (is_string($targetPlan['target_json_path'])) {
            $replayPlan['target_json_path'] = $targetPlan['target_json_path'];
        }
        if ($transportContext['headers'] !== array()) {
            $replayPlan['replay_headers'] = $transportContext['headers'];
        }
        if ($transportContext['cookies'] !== array()) {
            $replayPlan['replay_cookies'] = $transportContext['cookies'];
        }
        if (is_string($transportContext['body']) && $transportContext['body'] !== '') {
            $replayPlan['replay_body'] = $transportContext['body'];
        }
        if (is_string($transportContext['body_format'])) {
            $replayPlan['request_body_format'] = $transportContext['body_format'];
        }

        if ($sinkCategory === 'idor') {
            $idorPlan = $this->idorReplayPlan($requestQueryParams);
            $replayPlan = array_merge($replayPlan, $idorPlan);
        }

        return new VerificationJob(
            jobId: $jobId,
            candidateId: $candidate->id(),
            sinkCategory: $sinkCategory,
            oracleType: $oracleType,
            replayProfile: $this->replayProfile,
            createdAt: gmdate('c'),
            attemptCount: 0,
            status: 'pending',
            candidateSnapshot: $candidateSnapshot,
            replayPlan: $replayPlan,
            metadata: array(
                'phase' => 'phase_d_v1',
                'candidate_sink_category' => $candidateCategory,
            )
        );
    }

    /**
     * @return array{sink_category: string, oracle_type: string}|null
     */
    private function resolveTargetCategoryAndOracle(string $candidateCategory, array $requestQueryParams): ?array
    {
        if ($candidateCategory === 'xss' && $this->looksLikeIdorRequest($requestQueryParams)) {
            return array(
                'sink_category' => 'idor',
                'oracle_type' => 'idor_oracle',
            );
        }

        $oracleType = match ($candidateCategory) {
            'rce' => 'rce_oracle',
            'sqli' => 'sqli_oracle',
            'ssrf' => 'ssrf_oracle',
            'file' => 'file_oracle',
            'xss' => 'xss_oracle',
            'idor' => 'idor_oracle',
            'xxe' => 'xxe_oracle',
            default => null,
        };

        if (!is_string($oracleType)) {
            return null;
        }

        return array(
            'sink_category' => $candidateCategory,
            'oracle_type' => $oracleType,
        );
    }

    private function targetQueryParam(string $sinkCategory, array $queryParams): string
    {
        $preferred = $this->preferredTargetQueryParams($sinkCategory);
        foreach ($preferred as $preferredParam) {
            if (array_key_exists($preferredParam, $queryParams)) {
                return $preferredParam;
            }
        }

        foreach ($queryParams as $key => $value) {
            if (RequestParamPolicy::isRoutingParamName((string) $key)) {
                continue;
            }
            if (is_scalar($value)) {
                return (string) $key;
            }
        }

        foreach ($queryParams as $key => $value) {
            if (is_scalar($value)) {
                return (string) $key;
            }
        }

        return $preferred[0] ?? 'input';
    }

    /**
     * @param array<string, string> $headers
     * @return array{
     *   target_query_param: string,
     *   target_param_location: string,
     *   target_body_param: ?string,
     *   target_body_format: ?string,
     *   target_json_path: ?string
     * }
     */
    private function targetMutationPlan(
        string $sinkCategory,
        string $requestMethod,
        array $queryParams,
        array $headers,
        ?string $requestBody
    ): array {
        $targetQueryParam = $this->targetQueryParam($sinkCategory, $queryParams);
        $targetParamLocation = 'query';
        $targetBodyParam = null;
        $targetBodyFormat = null;
        $targetJsonPath = null;

        if ($requestMethod === 'POST' && ($this->isUrlEncodedBody($headers) || $this->isJsonBody($headers))) {
            $bodyParams = $this->isJsonBody($headers)
                ? $this->parseJsonBodyParams($requestBody)
                : $this->parseBodyParams($requestBody);
            if ($bodyParams !== array()) {
                if (array_key_exists($targetQueryParam, $bodyParams)) {
                    $targetBodyParam = $targetQueryParam;
                } else {
                    foreach ($this->preferredTargetBodyParams($sinkCategory, $this->isJsonBody($headers)) as $preferredParam) {
                        if (array_key_exists($preferredParam, $bodyParams)) {
                            $targetBodyParam = $preferredParam;
                            break;
                        }
                    }
                }

                if (!is_string($targetBodyParam)) {
                    foreach ($bodyParams as $key => $value) {
                        if (RequestParamPolicy::isRoutingParamName((string) $key)) {
                            continue;
                        }
                        $targetBodyParam = (string) $key;
                        break;
                    }
                }

                if (!is_string($targetBodyParam)) {
                    foreach ($bodyParams as $key => $value) {
                        $targetBodyParam = (string) $key;
                        break;
                    }
                }

                if (is_string($targetBodyParam)) {
                    $targetParamLocation = 'body';
                    if ($this->isJsonBody($headers)) {
                        $targetBodyFormat = 'json';
                        $targetJsonPath = $targetBodyParam;
                    }
                }
            }
        }

        return array(
            'target_query_param' => $targetQueryParam,
            'target_param_location' => $targetParamLocation,
            'target_body_param' => $targetBodyParam,
            'target_body_format' => $targetBodyFormat,
            'target_json_path' => $targetJsonPath,
        );
    }

    /**
     * @return list<string>
     */
    private function preferredTargetQueryParams(string $sinkCategory): array
    {
        return match ($sinkCategory) {
            'rce' => array('cmd', 'code', 'payload', 'expr', 'expression'),
            'ssrf' => array('url', 'uri', 'target'),
            'sqli' => array('q', 'query', 'sql'),
            'file' => array('path', 'file', 'filename'),
            'xss' => array('name', 'input', 'value'),
            'idor' => array('resource_id', 'id'),
            'xxe' => array('xml', 'doc', 'payload'),
            default => array('input'),
        };
    }

    /**
     * @return list<string>
     */
    private function preferredTargetBodyParams(string $sinkCategory, bool $jsonBody): array
    {
        if (!$jsonBody) {
            return $this->preferredTargetQueryParams($sinkCategory);
        }

        return match ($sinkCategory) {
            'rce' => array('task.command', 'command', 'cmd', 'task.cmd', 'code', 'payload'),
            'ssrf' => array('target.url', 'url', 'uri', 'target'),
            'sqli' => array('lookup.id', 'id', 'lookup.query', 'query', 'q', 'sql'),
            'file' => array('file.page', 'file.path', 'path', 'file', 'filename'),
            'xss' => array('input.value', 'input', 'name', 'value'),
            'idor' => array('resource.id', 'resource_id', 'id'),
            'xxe' => array('document.xml', 'xml', 'doc', 'payload'),
            default => array('input'),
        };
    }

    /**
     * @return array{
     *   idor_resource_param: string,
     *   idor_actor_param: string,
     *   idor_mode_param: string,
     *   idor_owner_actor?: string,
     *   idor_non_owner_actor?: string
     * }
     */
    private function idorReplayPlan(array $queryParams): array
    {
        $resourceParam = array_key_exists('resource_id', $queryParams) ? 'resource_id' : 'id';
        $actorParam = array_key_exists('actor_id', $queryParams) ? 'actor_id' : 'user_id';
        $modeParam = array_key_exists('mode', $queryParams) ? 'mode' : 'view';

        $plan = array(
            'idor_resource_param' => $resourceParam,
            'idor_actor_param' => $actorParam,
            'idor_mode_param' => $modeParam,
        );

        if (array_key_exists('owner_actor_id', $queryParams) && is_scalar($queryParams['owner_actor_id'])) {
            $plan['idor_owner_actor'] = (string) $queryParams['owner_actor_id'];
        }
        if (array_key_exists('non_owner_actor_id', $queryParams) && is_scalar($queryParams['non_owner_actor_id'])) {
            $plan['idor_non_owner_actor'] = (string) $queryParams['non_owner_actor_id'];
        }

        return $plan;
    }

    private function looksLikeIdorRequest(array $queryParams): bool
    {
        $hasResourceKey = array_key_exists('resource_id', $queryParams) || array_key_exists('id', $queryParams);
        $hasActorKey = array_key_exists('actor_id', $queryParams) || array_key_exists('user_id', $queryParams);

        return $hasResourceKey && $hasActorKey;
    }

    /**
     * @param array<string, mixed> $candidateSnapshot
     * @return array{headers: array<string, string>, cookies: array<string, string>, body: ?string, body_format: ?string}
     */
    private function transportContextFromCandidate(array $candidateSnapshot): array
    {
        $requestEvidence = is_array($candidateSnapshot['request_evidence'] ?? null)
            ? $candidateSnapshot['request_evidence']
            : array();
        $requestMetadata = is_array($requestEvidence['metadata'] ?? null)
            ? $requestEvidence['metadata']
            : array();

        $headers = array();
        if (is_array($requestMetadata['request_headers'] ?? null)) {
            foreach ($requestMetadata['request_headers'] as $headerName => $headerValue) {
                if (!is_scalar($headerValue)) {
                    continue;
                }
                $normalizedHeader = strtolower(trim((string) $headerName));
                if ($normalizedHeader === '') {
                    continue;
                }
                $headers[$normalizedHeader] = trim((string) $headerValue);
            }
        }
        ksort($headers);

        $cookies = array();
        if (is_array($requestMetadata['cookie_keys'] ?? null)) {
            foreach ($requestMetadata['cookie_keys'] as $cookieKey) {
                if (!is_scalar($cookieKey)) {
                    continue;
                }
                $normalizedCookie = trim((string) $cookieKey);
                if ($normalizedCookie === '') {
                    continue;
                }
                $cookies[$normalizedCookie] = '1';
            }
        }
        ksort($cookies);

        $body = null;
        if (is_scalar($requestMetadata['request_body'] ?? null)) {
            $resolvedBody = trim((string) $requestMetadata['request_body']);
            if ($resolvedBody !== '') {
                $body = $resolvedBody;
            }
        }
        $bodyFormat = null;
        if (is_scalar($requestMetadata['request_body_format'] ?? null)) {
            $resolvedFormat = strtolower(trim((string) $requestMetadata['request_body_format']));
            if (in_array($resolvedFormat, array('form', 'json'), true)) {
                $bodyFormat = $resolvedFormat;
            }
        }
        if ($bodyFormat === null && $body !== null && $this->isJsonBody($headers)) {
            $bodyFormat = 'json';
        }
        if ($bodyFormat === null && $body !== null && $this->isUrlEncodedBody($headers)) {
            $bodyFormat = 'form';
        }

        return array(
            'headers' => $headers,
            'cookies' => $cookies,
            'body' => $body,
            'body_format' => $bodyFormat,
        );
    }

    /**
     * @param array<string, string> $headers
     */
    private function isUrlEncodedBody(array $headers): bool
    {
        $contentType = strtolower(trim((string) ($headers['content-type'] ?? '')));
        if ($contentType === '') {
            return true;
        }

        return str_contains($contentType, 'application/x-www-form-urlencoded');
    }

    /**
     * @param array<string, string> $headers
     */
    private function isJsonBody(array $headers): bool
    {
        $contentType = strtolower(trim((string) ($headers['content-type'] ?? '')));
        return $contentType !== '' && str_contains($contentType, 'application/json');
    }

    /**
     * @return array<string, string>
     */
    private function parseBodyParams(?string $body): array
    {
        if (!is_string($body) || trim($body) === '') {
            return array();
        }

        $parsed = array();
        parse_str($body, $parsed);
        if (!is_array($parsed)) {
            return array();
        }

        $bodyParams = array();
        foreach ($parsed as $key => $value) {
            if (!is_scalar($value)) {
                continue;
            }
            $normalizedKey = trim((string) $key);
            if ($normalizedKey === '') {
                continue;
            }
            $bodyParams[$normalizedKey] = (string) $value;
        }

        return $bodyParams;
    }

    /**
     * @return array<string, string>
     */
    private function parseJsonBodyParams(?string $body): array
    {
        if (!is_string($body) || trim($body) === '') {
            return array();
        }

        $decoded = json_decode($body, true);
        if (!is_array($decoded)) {
            return array();
        }

        $bodyParams = array();
        $this->flattenJsonScalarPaths($decoded, '', $bodyParams);
        ksort($bodyParams);
        return $bodyParams;
    }

    /**
     * @param array<string, mixed> $value
     * @param array<string, string> $params
     */
    private function flattenJsonScalarPaths(array $value, string $prefix, array &$params): void
    {
        foreach ($value as $key => $inner) {
            $segment = trim((string) $key);
            if ($segment === '') {
                continue;
            }

            $path = $prefix === '' ? $segment : $prefix . '.' . $segment;
            if (is_array($inner)) {
                $this->flattenJsonScalarPaths($inner, $path, $params);
                continue;
            }

            if (is_scalar($inner) || $inner === null) {
                $params[$path] = $inner === null ? '' : (string) $inner;
            }
        }
    }
}
