<?php

declare(strict_types=1);

namespace PhpTaintTrace\Core;

use InvalidArgumentException;

final class TaintedValue
{
    private function __construct(
        private readonly mixed $value,
        private readonly TaintMetadata $metadata
    ) {
    }

    public static function clean(mixed $value): self
    {
        return new self($value, TaintMetadata::clean());
    }

    public static function tainted(mixed $value, string $source): self
    {
        return new self($value, TaintMetadata::fromSource($source));
    }

    public function value(): mixed
    {
        return $this->value;
    }

    public function metadata(): TaintMetadata
    {
        return $this->metadata;
    }

    public function isTainted(): bool
    {
        return $this->metadata->isTainted();
    }

    public function map(callable $transform): self
    {
        return new self($transform($this->value), $this->metadata);
    }

    public static function combine(callable $transform, self ...$values): self
    {
        if (count($values) === 0) {
            throw new InvalidArgumentException('combine() requires at least one TaintedValue.');
        }

        $merged = TaintMetadata::clean();
        $rawValues = array();
        foreach ($values as $value) {
            $merged = $merged->merge($value->metadata());
            $rawValues[] = $value->value();
        }

        return new self($transform(...$rawValues), $merged);
    }
}
