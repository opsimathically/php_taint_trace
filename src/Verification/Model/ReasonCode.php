<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Model;

use InvalidArgumentException;

enum ReasonCode: string
{
    case DETECTOR_TAINT_INPUT = 'DETECTOR_TAINT_INPUT';
    case DETECTOR_PAYLOAD_KEYWORD = 'DETECTOR_PAYLOAD_KEYWORD';
    case SINK_ARGUMENT_ROLE_PRIMARY = 'SINK_ARGUMENT_ROLE_PRIMARY';
    case TAINT_SOURCE_PRESENT = 'TAINT_SOURCE_PRESENT';
    case AUTHZ_EVIDENCE_UNAVAILABLE = 'AUTHZ_EVIDENCE_UNAVAILABLE';
    case AUTHZ_EVIDENCE_PARTIAL = 'AUTHZ_EVIDENCE_PARTIAL';
    case AUTHZ_EVIDENCE_PRESENT = 'AUTHZ_EVIDENCE_PRESENT';
    case CATEGORY_RCE = 'CATEGORY_RCE';
    case CATEGORY_SQLI = 'CATEGORY_SQLI';
    case CATEGORY_SSRF = 'CATEGORY_SSRF';
    case CATEGORY_FILE = 'CATEGORY_FILE';
    case CATEGORY_XSS = 'CATEGORY_XSS';
    case CATEGORY_IDOR = 'CATEGORY_IDOR';
    case CATEGORY_XXE = 'CATEGORY_XXE';

    public static function fromString(string $value): self
    {
        $normalized = self::normalize($value);
        if ($normalized === null) {
            throw new InvalidArgumentException(sprintf('Unsupported reason code: %s', $value));
        }

        return $normalized;
    }

    public static function normalize(string $value): ?self
    {
        $normalized = strtoupper(trim($value));
        return self::tryFrom($normalized);
    }

    /**
     * @return string[]
     */
    public static function values(): array
    {
        return array_map(
            static fn (self $reasonCode): string => $reasonCode->value,
            self::cases()
        );
    }
}
