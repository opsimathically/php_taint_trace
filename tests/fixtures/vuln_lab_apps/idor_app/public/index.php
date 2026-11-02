<?php

declare(strict_types=1);

/**
 * Intentionally vulnerable IDOR fixture:
 * - `mode=safe` enforces owner-only access.
 * - `mode=vuln` skips authorization checks.
 *
 * Uses `printf` as sink so detector emits an XSS-class candidate that the
 * verifier can promote to IDOR based on request-shape heuristics.
 */
$resourceId = (string) ($_GET['resource_id'] ?? '42');
$actorId = (string) ($_GET['actor_id'] ?? '1043');
$mode = (string) ($_GET['mode'] ?? 'vuln');

$ownerActorId = (string) ((int) $resourceId + 1000);
$resourceBody = sprintf('resource:%s owner:%s', $resourceId, $ownerActorId);

if ($mode === 'safe' && $actorId !== $ownerActorId) {
    http_response_code(403);
    echo 'forbidden';
    return;
}

printf('%s actor:%s mode:%s', $resourceBody, $actorId, $mode);
