<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit;

use PhpTaintTrace\Core\TaintedValue;
use PHPUnit\Framework\TestCase;

final class TaintedValueTest extends TestCase
{
    public function testMapPreservesTaintMetadata(): void
    {
        $input = TaintedValue::tainted('alice', 'query.id');
        $mapped = $input->map(static fn (string $value): string => strtoupper($value));

        self::assertSame('ALICE', $mapped->value());
        self::assertTrue($mapped->isTainted());
        self::assertSame(array('query.id'), $mapped->metadata()->sources());
    }

    public function testCombineMergesSources(): void
    {
        $a = TaintedValue::tainted('hello', 'query.a');
        $b = TaintedValue::tainted('world', 'post.b');
        $c = TaintedValue::clean('safe');

        $combined = TaintedValue::combine(
            static fn (string $one, string $two, string $three): string => $one . '-' . $two . '-' . $three,
            $a,
            $b,
            $c
        );

        self::assertSame('hello-world-safe', $combined->value());
        self::assertTrue($combined->isTainted());
        self::assertSame(array('post.b', 'query.a'), $combined->metadata()->sources());
    }
}
