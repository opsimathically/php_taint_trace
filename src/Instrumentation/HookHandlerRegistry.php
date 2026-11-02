<?php

declare(strict_types=1);

namespace PhpTaintTrace\Instrumentation;

use RuntimeException;

final class HookHandlerRegistry
{
    /**
     * @var array<string, callable(HookContext): void>
     */
    private array $handlers = array();

    public function __construct(private readonly bool $strict = false)
    {
    }

    /**
     * @param callable(HookContext): void $handler
     */
    public function register(string $hookId, callable $handler): void
    {
        $this->handlers[$hookId] = $handler;
    }

    /**
     * @return callable(HookContext): void
     */
    public function resolve(HookDefinition $hook): callable
    {
        if (isset($this->handlers[$hook->id()])) {
            return $this->handlers[$hook->id()];
        }

        if ($this->strict) {
            throw new RuntimeException(sprintf('Missing hook handler for %s', $hook->id()));
        }

        return static function (HookContext $context): void {
        };
    }
}
