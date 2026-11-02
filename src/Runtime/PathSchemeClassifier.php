<?php

declare(strict_types=1);

namespace PhpTaintTrace\Runtime;

use PhpTaintTrace\Core\TaintedValue;

final class PathSchemeClassifier
{
    /**
     * @var string[]
     */
    private const REMOTE_SCHEMES = array(
        'ftp',
        'ftps',
        'gopher',
        'http',
        'https',
    );

    public function scheme(mixed $pathValue): ?string
    {
        $path = $this->extractPathString($pathValue);
        if (!is_string($path) || $path === '') {
            return null;
        }

        $scheme = parse_url($path, PHP_URL_SCHEME);
        if (!is_string($scheme) || $scheme === '') {
            return null;
        }

        return strtolower($scheme);
    }

    public function isRemoteWrapper(mixed $pathValue): bool
    {
        $scheme = $this->scheme($pathValue);
        if ($scheme === null) {
            return false;
        }

        return in_array($scheme, self::REMOTE_SCHEMES, true);
    }

    private function extractPathString(mixed $pathValue): ?string
    {
        if ($pathValue instanceof TaintedValue) {
            $pathValue = $pathValue->value();
        }

        if (!is_string($pathValue)) {
            return null;
        }

        $normalizedPath = trim($pathValue);
        if ($normalizedPath === '') {
            return null;
        }

        return $normalizedPath;
    }
}
