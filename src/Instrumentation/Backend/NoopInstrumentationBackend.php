<?php

declare(strict_types=1);

namespace PhpTaintTrace\Instrumentation\Backend;

use PhpTaintTrace\Instrumentation\HookDefinition;
use PhpTaintTrace\Instrumentation\HookContext;
use PhpTaintTrace\Instrumentation\InstrumentationBackendInterface;
use PhpTaintTrace\Instrumentation\InstrumentationCapabilities;

final class NoopInstrumentationBackend implements InstrumentationBackendInterface
{
    public function backendName(): string
    {
        return 'noop';
    }

    public function capabilities(): InstrumentationCapabilities
    {
        return InstrumentationCapabilities::none();
    }

    /**
     * @param callable(HookContext): void $handler
     */
    public function registerHook(HookDefinition $hook, callable $handler): void
    {
    }

    public function markTainted(mixed &$value, bool $recursive = true, ?string $source = null): void
    {
    }

    public function isTainted(mixed $value, bool $recursive = true): bool
    {
        return false;
    }
}
