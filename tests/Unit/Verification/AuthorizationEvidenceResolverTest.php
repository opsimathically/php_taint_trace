<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit\Verification;

use PhpTaintTrace\Verification\Detector\AuthorizationEvidenceResolver;
use PhpTaintTrace\Verification\Model\RequestEvidence;
use PHPUnit\Framework\TestCase;

final class AuthorizationEvidenceResolverTest extends TestCase
{
    public function testResolveDefaultsToUnavailableWithNullSafeBehavior(): void
    {
        $resolver = new AuthorizationEvidenceResolver();
        $requestEvidence = new RequestEvidence(
            timestamp: '2026-04-22T00:00:00+00:00',
            sapi: 'cli',
            requestMethod: null,
            requestUri: null
        );

        $evidence = $resolver->resolve($requestEvidence, array(), array());
        self::assertTrue($evidence->isUnavailable());
        self::assertFalse($evidence->isPresent());
        self::assertSame(array('resolver' => 'phase_a_scaffold'), $evidence->metadata());
    }

    public function testResolveBuildsPartialAndPresentEvidenceFromInputs(): void
    {
        $resolver = new AuthorizationEvidenceResolver();

        $partial = $resolver->resolve(
            new RequestEvidence(
                timestamp: '2026-04-22T00:00:00+00:00',
                sapi: 'fpm-fcgi',
                requestMethod: 'GET',
                requestUri: '/items?id=42'
            ),
            array('id' => '42'),
            array()
        );
        self::assertTrue($partial->isPartial());
        self::assertSame('42', $partial->resourceId());
        self::assertSame('read', $partial->operation());

        $present = $resolver->resolve(
            new RequestEvidence(
                timestamp: '2026-04-22T00:00:00+00:00',
                sapi: 'fpm-fcgi',
                requestMethod: 'DELETE',
                requestUri: '/items?id=42'
            ),
            array('id' => '42'),
            array('REMOTE_USER' => 'alice')
        );
        self::assertTrue($present->isPresent());
        self::assertSame('alice', $present->principalId());
        self::assertSame('42', $present->resourceId());
        self::assertSame('delete', $present->operation());
    }
}
