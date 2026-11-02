<?php

declare(strict_types=1);

namespace PhpTaintTrace\Instrumentation\Backend;

use PhpTaintTrace\Instrumentation\HookDefinition;
use PhpTaintTrace\Instrumentation\HookContext;
use PhpTaintTrace\Instrumentation\InstrumentationBackendInterface;
use PhpTaintTrace\Instrumentation\InstrumentationCapabilities;
use PhpTaintTrace\Instrumentation\HookKind;
use RuntimeException;

final class XmarkExtensionBackend implements InstrumentationBackendInterface
{
    /**
     * @var null|callable(HookDefinition, callable(HookContext): void): void
     */
    private mixed $registerHook;

    /**
     * @var null|callable(mixed, bool, ?string): void
     */
    private mixed $marker;

    /**
     * @var null|callable(mixed, bool): bool
     */
    private mixed $checker;

    /**
     * @var null|callable(string, string, string, string, callable(array<string, mixed>): mixed): bool
     */
    private mixed $nativeHookRegistrar;

    /**
     * @var null|callable(string|int, callable(array<string, mixed>): mixed, string, ?string): bool
     */
    private mixed $nativeOpcodeRegistrar;

    /**
     * @param null|callable(HookDefinition, callable(HookContext): void): void $registerHook
     * @param null|callable(mixed, bool, ?string): void $marker
     * @param null|callable(mixed, bool): bool $checker
     * @param null|callable(string, string, string, string, callable(array<string, mixed>): mixed): bool $nativeHookRegistrar
     * @param null|callable(string|int, callable(array<string, mixed>): mixed, string, ?string): bool $nativeOpcodeRegistrar
     */
    public function __construct(
        ?callable $registerHook = null,
        ?callable $marker = null,
        ?callable $checker = null,
        private readonly ?InstrumentationCapabilities $capabilityOverride = null,
        ?callable $nativeHookRegistrar = null,
        ?callable $nativeOpcodeRegistrar = null
    ) {
        $this->registerHook = $registerHook;
        $this->marker = $marker;
        $this->checker = $checker;
        $this->nativeHookRegistrar = $nativeHookRegistrar;
        $this->nativeOpcodeRegistrar = $nativeOpcodeRegistrar;
    }

    public function backendName(): string
    {
        return 'xmark-extension';
    }

    public function capabilities(): InstrumentationCapabilities
    {
        if ($this->capabilityOverride !== null) {
            return $this->capabilityOverride;
        }

        $hasRegistrar = $this->registerHook !== null || $this->hasNativeHookRegistrar();
        $taintTracking = ($this->marker !== null && $this->checker !== null) ||
            (function_exists('xmark') && function_exists('xcheck'));
        $opcodeHooks = $this->registerHook !== null || $this->hasNativeOpcodeRegistrar();

        return new InstrumentationCapabilities(
            functionHooks: $hasRegistrar,
            methodHooks: $hasRegistrar,
            opcodeHooks: $opcodeHooks,
            taintTracking: $taintTracking,
            symbolRenaming: false
        );
    }

    /**
     * @param callable(HookContext): void $handler
     */
    public function registerHook(HookDefinition $hook, callable $handler): void
    {
        if ($this->registerHook === null) {
            if (
                $hook->kind() === HookKind::OPCODE &&
                $this->hasNativeOpcodeRegistrar()
            ) {
                $bridge = $this->nativeContextBridge($hook, $handler);
                $registered = $this->registerNativeOpcodeHook(
                    $hook->target(),
                    $bridge,
                    $hook->phase()->value,
                    $hook->id()
                );
                if (!$registered) {
                    throw new RuntimeException(sprintf(
                        'Native opcode hook registration failed for hook "%s".',
                        $hook->id()
                    ));
                }
                return;
            }

            if (!$this->hasNativeHookRegistrar()) {
                throw new RuntimeException('No extension hook registrar configured.');
            }

            $bridge = $this->nativeContextBridge($hook, $handler);
            $registered = $this->registerNativeHook(
                $hook->id(),
                $hook->kind()->value,
                $hook->target(),
                $hook->phase()->value,
                $bridge
            );
            if (!$registered) {
                throw new RuntimeException(sprintf(
                    'Native hook registration failed for hook "%s".',
                    $hook->id()
                ));
            }

            return;
        }

        ($this->registerHook)($hook, $handler);
    }

    public function markTainted(mixed &$value, bool $recursive = true, ?string $source = null): void
    {
        if ($this->marker !== null) {
            ($this->marker)($value, $recursive, $source);
            return;
        }

        if (function_exists('xmark')) {
            if (is_string($value)) {
                xmark($value);
                return;
            }

            if ($recursive && is_array($value)) {
                foreach ($value as &$inner) {
                    $this->markTainted($inner, true, $source);
                }
                unset($inner);
            }
        }
    }

    public function isTainted(mixed $value, bool $recursive = true): bool
    {
        if ($this->checker !== null) {
            return (bool) ($this->checker)($value, $recursive);
        }

        if (!function_exists('xcheck')) {
            return false;
        }

        if (is_string($value)) {
            return (bool) xcheck($value);
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
     * @param callable(HookContext): mixed $handler
     * @return callable(array<string, mixed>): mixed
     */
    private function nativeContextBridge(HookDefinition $hook, callable $handler): callable
    {
        return function (array $nativeContext) use ($hook, $handler): mixed {
            $arguments = $nativeContext['arguments'] ?? array();
            if (!is_array($arguments)) {
                $arguments = array();
            }

            $metadata = $nativeContext['metadata'] ?? array();
            if (!is_array($metadata)) {
                $metadata = array();
            }

            $phase = (string) ($nativeContext['phase'] ?? 'before');
            $hasResult = (bool) ($nativeContext['has_result'] ?? false);
            $domain = (string) ($hook->metadata()['domain'] ?? '');
            $transformDomain = in_array($domain, array('filter', 'opcode'), true);

            if ($hook->phase()->value === 'replace') {
                if ($transformDomain && !$hasResult) {
                    return null;
                }

                if (!$transformDomain && $hasResult) {
                    return null;
                }
            }

            $usePostContext = $hasResult || $phase === 'after' || $hook->kind() === HookKind::OPCODE;

            $context = $usePostContext
                ? HookContext::forPostHook($hook, $arguments, $nativeContext['result'] ?? null, $metadata)
                : HookContext::forPreHook($hook, $arguments, $metadata);

            return $this->normalizeNativeReturn($handler($context));
        };
    }

    private function normalizeNativeReturn(mixed $value): mixed
    {
        if ($value instanceof \PhpTaintTrace\Core\TaintedValue) {
            $raw = $this->normalizeNativeReturn($value->value());
            if ($value->isTainted()) {
                $this->markTainted($raw, true, 'backend.bridge');
            }

            return $raw;
        }

        if (is_array($value)) {
            $result = array();
            foreach ($value as $key => $inner) {
                $result[$key] = $this->normalizeNativeReturn($inner);
            }

            return $result;
        }

        return $value;
    }

    private function hasNativeHookRegistrar(): bool
    {
        return $this->nativeHookRegistrar !== null || function_exists('xmark_register_hook');
    }

    private function hasNativeOpcodeRegistrar(): bool
    {
        return $this->nativeOpcodeRegistrar !== null || function_exists('xregister_opcode_callback');
    }

    /**
     * @param callable(array<string, mixed>): mixed $bridge
     */
    private function registerNativeHook(
        string $id,
        string $kind,
        string $target,
        string $phase,
        callable $bridge
    ): bool {
        if ($this->nativeHookRegistrar !== null) {
            return (bool) ($this->nativeHookRegistrar)($id, $kind, $target, $phase, $bridge);
        }

        return (bool) xmark_register_hook($id, $kind, $target, $phase, $bridge);
    }

    /**
     * @param callable(array<string, mixed>): mixed $bridge
     */
    private function registerNativeOpcodeHook(
        string|int $opcode,
        callable $bridge,
        string $phase,
        ?string $id
    ): bool {
        if ($this->nativeOpcodeRegistrar !== null) {
            return (bool) ($this->nativeOpcodeRegistrar)($opcode, $bridge, $phase, $id);
        }

        return (bool) xregister_opcode_callback($opcode, $bridge, $phase, $id);
    }
}
