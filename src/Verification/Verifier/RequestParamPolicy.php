<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Verifier;

final class RequestParamPolicy
{
    /**
     * @var list<string>
     */
    private const ROUTING_PARAM_NAMES = array(
        'sink',
        'mode',
        'action',
        'route',
        'controller',
        'method',
        'page',
        'view',
        'feature',
        'op',
        'csrf',
        '_token',
        'token',
    );

    public static function isRoutingParamName(string $name): bool
    {
        $normalized = strtolower(trim($name));
        if ($normalized === '') {
            return false;
        }

        return in_array($normalized, self::ROUTING_PARAM_NAMES, true);
    }

    /**
     * @return array<string, mixed>
     */
    public static function parseRequestUriQueryParams(string $requestUri): array
    {
        $query = parse_url($requestUri, PHP_URL_QUERY);
        if (!is_string($query)) {
            return array();
        }

        $parsed = array();
        parse_str($query, $parsed);
        return is_array($parsed) ? $parsed : array();
    }
}
