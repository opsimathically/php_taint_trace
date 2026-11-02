<?php

declare(strict_types=1);

namespace PhpTaintTrace\Instrumentation;

final class HookContext
{
    /**
     * @param array<int, mixed> $arguments
     * @param array<string, mixed> $metadata
     */
    public function __construct(
        private readonly HookDefinition $hook,
        private readonly array $arguments = array(),
        private readonly mixed $result = null,
        private readonly bool $hasResult = false,
        private readonly array $metadata = array()
    ) {
    }

    /**
     * @param array<string, mixed> $metadata
     */
    public static function forPreHook(HookDefinition $hook, array $arguments, array $metadata = array()): self
    {
        return new self($hook, $arguments, null, false, $metadata);
    }

    /**
     * @param array<string, mixed> $metadata
     */
    public static function forPostHook(
        HookDefinition $hook,
        array $arguments,
        mixed $result,
        array $metadata = array()
    ): self
    {
        return new self($hook, $arguments, $result, true, $metadata);
    }

    public function hook(): HookDefinition
    {
        return $this->hook;
    }

    /**
     * @return array<int, mixed>
     */
    public function arguments(): array
    {
        return $this->arguments;
    }

    public function hasResult(): bool
    {
        return $this->hasResult;
    }

    public function result(): mixed
    {
        return $this->result;
    }

    /**
     * @return array<string, mixed>
     */
    public function metadata(): array
    {
        return $this->metadata;
    }
}
