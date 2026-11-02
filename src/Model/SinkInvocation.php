<?php

declare(strict_types=1);

namespace PhpTaintTrace\Model;

use PhpTaintTrace\Core\TaintedValue;

final class SinkInvocation
{
    /**
     * @param array<int, mixed> $arguments
     * @param array<string, mixed> $metadata
     */
    public function __construct(
        private readonly string $sinkName,
        private readonly SinkCategory $sinkCategory,
        private readonly array $arguments,
        private readonly array $metadata = array()
    ) {
    }

    public function sinkName(): string
    {
        return $this->sinkName;
    }

    public function sinkCategory(): SinkCategory
    {
        return $this->sinkCategory;
    }

    /**
     * @return array<int, mixed>
     */
    public function arguments(): array
    {
        return $this->arguments;
    }

    /**
     * @return array<string, mixed>
     */
    public function metadata(): array
    {
        return $this->metadata;
    }

    public function hasTaintedInput(): bool
    {
        foreach ($this->arguments as $argument) {
            if ($argument instanceof TaintedValue && $argument->isTainted()) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return string[]
     */
    public function stringArguments(): array
    {
        $result = array();
        foreach ($this->arguments as $argument) {
            $this->appendStringValues($argument, $result);
        }

        return $result;
    }

    /**
     * @param mixed $value
     * @param array<int, string> $strings
     */
    private function appendStringValues(mixed $value, array &$strings): void
    {
        if ($value instanceof TaintedValue) {
            $value = $value->value();
        }

        if (is_string($value)) {
            $strings[] = $value;
            return;
        }

        if (is_array($value)) {
            foreach ($value as $inner) {
                $this->appendStringValues($inner, $strings);
            }
        }
    }
}
