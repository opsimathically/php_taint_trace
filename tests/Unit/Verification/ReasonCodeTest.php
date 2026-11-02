<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit\Verification;

use PhpTaintTrace\Verification\Model\ReasonCode;
use PHPUnit\Framework\TestCase;

final class ReasonCodeTest extends TestCase
{
    public function testValuesContainPhaseAReasonCodeSet(): void
    {
        self::assertSame(
            array(
                'DETECTOR_TAINT_INPUT',
                'DETECTOR_PAYLOAD_KEYWORD',
                'SINK_ARGUMENT_ROLE_PRIMARY',
                'TAINT_SOURCE_PRESENT',
                'AUTHZ_EVIDENCE_UNAVAILABLE',
                'AUTHZ_EVIDENCE_PARTIAL',
                'AUTHZ_EVIDENCE_PRESENT',
                'CATEGORY_RCE',
                'CATEGORY_SQLI',
                'CATEGORY_SSRF',
                'CATEGORY_FILE',
                'CATEGORY_XSS',
                'CATEGORY_IDOR',
                'CATEGORY_XXE',
            ),
            ReasonCode::values()
        );
    }

    public function testNormalizeIsCaseInsensitiveAndNullSafe(): void
    {
        self::assertSame(ReasonCode::CATEGORY_RCE, ReasonCode::normalize('category_rce'));
        self::assertSame(ReasonCode::CATEGORY_XSS, ReasonCode::normalize('CATEGORY_XSS'));
        self::assertNull(ReasonCode::normalize('not_a_real_code'));
    }
}
