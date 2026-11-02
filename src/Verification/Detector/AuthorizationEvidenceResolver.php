<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Detector;

use PhpTaintTrace\Verification\Model\AuthorizationEvidence;
use PhpTaintTrace\Verification\Model\RequestEvidence;

final class AuthorizationEvidenceResolver
{
    /**
     * @param array<string, mixed>|null $request
     * @param array<string, mixed>|null $server
     */
    public function resolve(RequestEvidence $requestEvidence, ?array $request = null, ?array $server = null): AuthorizationEvidence
    {
        $requestData = $request ?? $this->normalizeSuperglobal($_REQUEST ?? array());
        $serverData = $server ?? $this->normalizeSuperglobal($_SERVER ?? array());

        $principalId = $this->resolvePrincipalId($serverData);
        $resourceId = $this->resolveResourceId($requestData);
        $operation = $this->resolveOperation($requestEvidence->requestMethod());

        return new AuthorizationEvidence(
            $principalId,
            $resourceId,
            $operation,
            array('resolver' => 'phase_a_scaffold')
        );
    }

    /**
     * @param array<string, mixed> $server
     */
    private function resolvePrincipalId(array $server): ?string
    {
        $candidates = array(
            'REMOTE_USER',
            'PHP_AUTH_USER',
            'AUTH_USER',
            'HTTP_X_FORWARDED_USER',
            'HTTP_X_AUTH_USER',
        );

        foreach ($candidates as $key) {
            if (!array_key_exists($key, $server)) {
                continue;
            }

            $value = $server[$key];
            if (!is_scalar($value)) {
                continue;
            }

            $resolved = trim((string) $value);
            if ($resolved !== '') {
                return $resolved;
            }
        }

        return null;
    }

    /**
     * @param array<string, mixed> $request
     */
    private function resolveResourceId(array $request): ?string
    {
        $candidateKeys = array(
            'id',
            'resource_id',
            'object_id',
            'user_id',
            'account_id',
            'document_id',
        );

        foreach ($candidateKeys as $key) {
            if (!array_key_exists($key, $request)) {
                continue;
            }

            $value = $request[$key];
            if (!is_scalar($value)) {
                continue;
            }

            $resolved = trim((string) $value);
            if ($resolved !== '') {
                return $resolved;
            }
        }

        return null;
    }

    private function resolveOperation(?string $requestMethod): ?string
    {
        if ($requestMethod === null) {
            return null;
        }

        return match (strtoupper($requestMethod)) {
            'GET', 'HEAD', 'OPTIONS' => 'read',
            'POST' => 'create',
            'PUT', 'PATCH' => 'update',
            'DELETE' => 'delete',
            default => null,
        };
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
}
