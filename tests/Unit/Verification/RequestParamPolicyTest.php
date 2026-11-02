<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit\Verification;

use PhpTaintTrace\Verification\Verifier\RequestParamPolicy;
use PHPUnit\Framework\TestCase;

final class RequestParamPolicyTest extends TestCase
{
    public function testIsRoutingParamNameNormalizesInput(): void
    {
        self::assertTrue(RequestParamPolicy::isRoutingParamName('sink'));
        self::assertTrue(RequestParamPolicy::isRoutingParamName('  _token  '));
        self::assertTrue(RequestParamPolicy::isRoutingParamName('METHOD'));
        self::assertFalse(RequestParamPolicy::isRoutingParamName('cmd'));
        self::assertFalse(RequestParamPolicy::isRoutingParamName(''));
    }

    public function testParseRequestUriQueryParamsParsesQueryAndDefaultsToEmptyArray(): void
    {
        self::assertSame(array(), RequestParamPolicy::parseRequestUriQueryParams('/rce'));

        self::assertSame(
            array(
                'sink' => 'eval',
                'cmd' => 'echo xtanzi',
                'arr' => array('x'),
            ),
            RequestParamPolicy::parseRequestUriQueryParams('/rce?sink=eval&cmd=echo%20xtanzi&arr%5B0%5D=x')
        );
    }
}
