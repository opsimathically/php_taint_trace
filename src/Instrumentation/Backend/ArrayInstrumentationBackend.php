<?php

declare(strict_types=1);

namespace PhpTaintTrace\Instrumentation\Backend;

use PhpTaintTrace\Core\TaintedValue;
use PhpTaintTrace\Instrumentation\HookDefinition;
use PhpTaintTrace\Instrumentation\HookContext;
use PhpTaintTrace\Instrumentation\InstrumentationBackendInterface;
use PhpTaintTrace\Instrumentation\InstrumentationCapabilities;
use RuntimeException;

final class ArrayInstrumentationBackend implements InstrumentationBackendInterface
{
    /**
     * @var array<string, HookDefinition>
     */
    private array $hooks = array();

    /**
     * @var array<string, callable(HookContext): void>
     */
    private array $handlers = array();

    /**
     * @var array<int, array<string, mixed>>
     */
    private array $marks = array();

    public function __construct(
        private readonly InstrumentationCapabilities $capabilities = new InstrumentationCapabilities(
            functionHooks: true,
            methodHooks: true,
            opcodeHooks: true,
            taintTracking: true,
            symbolRenaming: false
        )
    ) {
    }

    public function backendName(): string
    {
        return 'array-backend';
    }

    public function capabilities(): InstrumentationCapabilities
    {
        return $this->capabilities;
    }

    /**
     * @param callable(HookContext): void $handler
     */
    public function registerHook(HookDefinition $hook, callable $handler): void
    {
        $this->hooks[$hook->id()] = $hook;
        $this->handlers[$hook->id()] = $handler;
    }

    public function markTainted(mixed &$value, bool $recursive = true, ?string $source = null): void
    {
        $this->marks[] = array(
            'source' => $source,
            'type' => get_debug_type($value),
            'recursive' => $recursive,
        );
    }

    public function isTainted(mixed $value, bool $recursive = true): bool
    {
        if ($value instanceof TaintedValue) {
            return $value->isTainted();
        }

        if ($recursive && is_array($value)) {
            foreach ($value as $inner) {
                if ($this->isTainted($inner, true)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * @return array<string, HookDefinition>
     */
    public function hooks(): array
    {
        return $this->hooks;
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    public function marks(): array
    {
        return $this->marks;
    }

    /**
     * @param array<int, mixed> $arguments
     * @param array<string, mixed> $metadata
     */
    public function dispatchPreHook(string $hookId, array $arguments, array $metadata = array()): mixed
    {
        $this->assertHookExists($hookId);
        return ($this->handlers[$hookId])(HookContext::forPreHook($this->hooks[$hookId], $arguments, $metadata));
    }

    /**
     * @param array<int, mixed> $arguments
     * @param array<string, mixed> $metadata
     */
    public function dispatchPostHook(string $hookId, array $arguments, mixed $result, array $metadata = array()): mixed
    {
        $this->assertHookExists($hookId);
        return ($this->handlers[$hookId])(HookContext::forPostHook($this->hooks[$hookId], $arguments, $result, $metadata));
    }

    private function assertHookExists(string $hookId): void
    {
        if (!isset($this->hooks[$hookId]) || !isset($this->handlers[$hookId])) {
            throw new RuntimeException(sprintf('Hook not registered: %s', $hookId));
        }
    }
}
