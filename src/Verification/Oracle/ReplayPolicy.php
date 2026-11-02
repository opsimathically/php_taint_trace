<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Oracle;

use PhpTaintTrace\Verification\Model\VerificationJob;
use PhpTaintTrace\Verification\Model\VerificationOutcome;
use PhpTaintTrace\Verification\Verifier\RequestParamPolicy;
use PhpTaintTrace\Verification\Verifier\ReplayRequest;

final class ReplayPolicy
{
    /**
     * @param string[] $defaultAllowedMethods
     */
    public static function enforceMethodPolicy(
        VerificationJob $job,
        ReplayRequest $request,
        array $defaultAllowedMethods,
        string $legacyReasonCode,
        string $legacySummary
    ): ?OracleDecision {
        $allowed = self::resolveAllowedMethods($job, $defaultAllowedMethods);
        $method = strtoupper($request->method());
        if (in_array($method, $allowed, true)) {
            return null;
        }

        return new OracleDecision(
            VerificationOutcome::BLOCKED_BY_POLICY,
            array('VERIFIER_REPLAY_METHOD_BLOCKED', $legacyReasonCode),
            sprintf(
                '%s (method=%s, allowed=%s)',
                $legacySummary,
                $method,
                implode(',', $allowed)
            ),
            array()
        );
    }

    /**
     * @return array{location: string, parameter: string}|null
     */
    public static function resolveTargetParameter(VerificationJob $job, ReplayRequest $request): ?array
    {
        $plan = $job->replayPlan();

        $plannedLocation = self::normalizeLocation($plan['target_param_location'] ?? null);
        $plannedQuery = self::normalizeParamName($plan['target_query_param'] ?? null);
        $plannedBody = self::normalizeParamName($plan['target_body_param'] ?? null);

        if (
            $plannedLocation === 'body' &&
            $plannedBody !== null &&
            array_key_exists($plannedBody, $request->bodyParams())
        ) {
            return array('location' => 'body', 'parameter' => $plannedBody);
        }

        if (
            $plannedLocation === 'query' &&
            $plannedQuery !== null &&
            array_key_exists($plannedQuery, $request->queryParams())
        ) {
            return array('location' => 'query', 'parameter' => $plannedQuery);
        }

        if ($plannedQuery !== null && array_key_exists($plannedQuery, $request->queryParams())) {
            return array('location' => 'query', 'parameter' => $plannedQuery);
        }

        if ($plannedBody !== null && array_key_exists($plannedBody, $request->bodyParams())) {
            return array('location' => 'body', 'parameter' => $plannedBody);
        }

        $preferredQuery = self::selectPreferredParam($job->sinkCategory(), $request->queryParams());
        if ($preferredQuery !== null) {
            return array('location' => 'query', 'parameter' => $preferredQuery);
        }

        $preferredBody = self::selectPreferredParam($job->sinkCategory(), $request->bodyParams());
        if ($preferredBody !== null) {
            return array('location' => 'body', 'parameter' => $preferredBody);
        }

        foreach ($request->queryParams() as $key => $value) {
            if (RequestParamPolicy::isRoutingParamName((string) $key)) {
                continue;
            }
            return array('location' => 'query', 'parameter' => (string) $key);
        }

        foreach ($request->bodyParams() as $key => $value) {
            if (RequestParamPolicy::isRoutingParamName((string) $key)) {
                continue;
            }
            return array('location' => 'body', 'parameter' => (string) $key);
        }

        foreach ($request->queryParams() as $key => $value) {
            return array('location' => 'query', 'parameter' => (string) $key);
        }

        foreach ($request->bodyParams() as $key => $value) {
            return array('location' => 'body', 'parameter' => (string) $key);
        }

        return null;
    }

    /**
     * @param array{location: string, parameter: string} $target
     */
    public static function mutateRequest(
        ReplayRequest $request,
        array $target,
        string $value,
        string $payloadLabel
    ): ReplayRequest {
        return $request->withMutatedParameter(
            $target['location'],
            $target['parameter'],
            $value,
            $payloadLabel
        );
    }

    /**
     * @param string[] $defaultAllowedMethods
     * @return string[]
     */
    private static function resolveAllowedMethods(VerificationJob $job, array $defaultAllowedMethods): array
    {
        $plan = $job->replayPlan();
        $rawAllowed = is_array($plan['allowed_methods'] ?? null) ? $plan['allowed_methods'] : null;

        $normalized = array();
        if (is_array($rawAllowed)) {
            foreach ($rawAllowed as $method) {
                if (!is_scalar($method)) {
                    continue;
                }
                $resolved = strtoupper(trim((string) $method));
                if ($resolved === '') {
                    continue;
                }
                $normalized[] = $resolved;
            }
        }

        if ($normalized === array()) {
            foreach ($defaultAllowedMethods as $method) {
                $resolved = strtoupper(trim($method));
                if ($resolved === '') {
                    continue;
                }
                $normalized[] = $resolved;
            }
        }

        $normalized = array_values(array_unique($normalized));
        sort($normalized);
        return $normalized;
    }

    private static function normalizeLocation(mixed $value): ?string
    {
        if (!is_scalar($value)) {
            return null;
        }

        $resolved = strtolower(trim((string) $value));
        return in_array($resolved, array('query', 'body'), true) ? $resolved : null;
    }

    private static function normalizeParamName(mixed $value): ?string
    {
        if (!is_scalar($value)) {
            return null;
        }

        $resolved = trim((string) $value);
        return $resolved === '' ? null : $resolved;
    }

    /**
     * @param array<string, string> $params
     */
    private static function selectPreferredParam(string $sinkCategory, array $params): ?string
    {
        if ($params === array()) {
            return null;
        }

        $preferredNames = self::preferredParamNames($sinkCategory);
        foreach ($preferredNames as $preferredName) {
            foreach ($params as $key => $_value) {
                $paramName = (string) $key;
                if (RequestParamPolicy::isRoutingParamName($paramName)) {
                    continue;
                }
                if (self::paramNameMatchesPreferred($paramName, $preferredName)) {
                    return $paramName;
                }
            }
        }

        return null;
    }

    /**
     * @return string[]
     */
    private static function preferredParamNames(string $sinkCategory): array
    {
        return match ($sinkCategory) {
            'rce' => array('cmd', 'code', 'payload', 'expr', 'expression'),
            'ssrf' => array('url', 'uri', 'target', 'endpoint'),
            'sqli' => array('q', 'query', 'sql', 'statement'),
            'file' => array('path', 'file', 'filename'),
            'xss' => array('name', 'input', 'value', 'content'),
            'idor' => array('resource_id', 'id', 'object_id'),
            'xxe' => array('xml', 'doc', 'payload'),
            default => array(),
        };
    }

    private static function paramNameMatchesPreferred(string $paramName, string $preferred): bool
    {
        $normalizedName = strtolower(trim($paramName));
        $normalizedPreferred = strtolower(trim($preferred));
        if ($normalizedName === $normalizedPreferred) {
            return true;
        }

        if (str_ends_with($normalizedName, '[' . $normalizedPreferred . ']')) {
            return true;
        }

        if (str_contains($normalizedName, $normalizedPreferred)) {
            return true;
        }

        $tokens = preg_split('/[^a-z0-9_]+/', $normalizedName);
        if (!is_array($tokens)) {
            return false;
        }

        return in_array($normalizedPreferred, $tokens, true);
    }
}
