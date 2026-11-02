<?php

declare(strict_types=1);

namespace PhpTaintTrace\Instrumentation;

interface InstrumentationBackendInterface
{
    public function backendName(): string;

    public function capabilities(): InstrumentationCapabilities;

    /**
     * @param callable(HookContext): void $handler
     */
    public function registerHook(HookDefinition $hook, callable $handler): void;

    public function markTainted(mixed &$value, bool $recursive = true, ?string $source = null): void;

    public function isTainted(mixed $value, bool $recursive = true): bool;
}
