<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit;

use PhpTaintTrace\Core\TaintedValue;
use PhpTaintTrace\Runtime\PathSchemeClassifier;
use PHPUnit\Framework\TestCase;

final class PathSchemeClassifierTest extends TestCase
{
    public function testSchemeExtractionAndRemoteWrapperDetection(): void
    {
        $classifier = new PathSchemeClassifier();

        self::assertSame('https', $classifier->scheme('https://example.test/data'));
        self::assertTrue($classifier->isRemoteWrapper('https://example.test/data'));

        self::assertSame('file', $classifier->scheme('file:///tmp/data.txt'));
        self::assertFalse($classifier->isRemoteWrapper('file:///tmp/data.txt'));

        self::assertNull($classifier->scheme('/tmp/data.txt'));
        self::assertFalse($classifier->isRemoteWrapper('/tmp/data.txt'));
    }

    public function testTaintedValuesAreUnwrappedDuringClassification(): void
    {
        $classifier = new PathSchemeClassifier();

        $remote = TaintedValue::tainted('gopher://127.0.0.1:70/_', 'query.url');
        $local = TaintedValue::tainted('/var/www/index.php', 'query.path');

        self::assertSame('gopher', $classifier->scheme($remote));
        self::assertTrue($classifier->isRemoteWrapper($remote));
        self::assertFalse($classifier->isRemoteWrapper($local));
    }
}
