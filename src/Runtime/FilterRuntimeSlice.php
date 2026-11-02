<?php

declare(strict_types=1);

namespace PhpTaintTrace\Runtime;

use PhpTaintTrace\Core\TaintedValue;
use PhpTaintTrace\Instrumentation\BaselineHookPlan;
use PhpTaintTrace\Instrumentation\HookDefinition;
use PhpTaintTrace\Instrumentation\HookHandlerRegistry;
use PhpTaintTrace\Instrumentation\InstrumentationBackendInterface;
use PhpTaintTrace\Instrumentation\InstrumentationBootstrapReport;
use PhpTaintTrace\Instrumentation\LegacyBaselineHookPlanFactory;
use PhpTaintTrace\Instrumentation\RequestTaintSeeder;
use PhpTaintTrace\Instrumentation\RuntimeInstrumentationBootstrap;

final class FilterRuntimeSlice
{
    public function __construct(
        private readonly InstrumentationBackendInterface $backend
    ) {
    }

    public function bootstrap(): InstrumentationBootstrapReport
    {
        $handlers = new HookHandlerRegistry(true);
        foreach ($this->filterHookPlan()->hooks() as $hook) {
            $hookId = $hook->id();
            $handlers->register($hookId, function ($context) use ($hookId): mixed {
                return $this->applyFilter($hookId, $context->arguments());
            });
        }

        $bootstrap = new RuntimeInstrumentationBootstrap($this->backend);
        return $bootstrap->bootstrap($this->filterHookPlan(), $handlers);
    }

    public function requestTaintSeeder(): RequestTaintSeeder
    {
        return new RequestTaintSeeder($this->backend);
    }

    private function filterHookPlan(): BaselineHookPlan
    {
        $hooks = array_filter(
            LegacyBaselineHookPlanFactory::create()->hooks(),
            static fn (HookDefinition $hook): bool => str_starts_with($hook->id(), 'filter.')
        );

        return new BaselineHookPlan(...array_values($hooks));
    }

    /**
     * @param array<int, mixed> $arguments
     */
    private function applyFilter(string $hookId, array $arguments): mixed
    {
        return match ($hookId) {
            'filter.base64_decode' => $this->propagateFrom(
                $this->invokeBuiltin('base64_decode', $arguments),
                $arguments[0] ?? null
            ),
            'filter.basename' => $this->propagateFrom(
                $this->invokeBuiltin('basename', $arguments),
                $arguments[0] ?? null
            ),
            'filter.dirname' => $this->propagateFrom(
                $this->invokeBuiltin('dirname', $arguments),
                $arguments[0] ?? null
            ),
            'filter.explode' => $this->propagateFrom(
                $this->invokeBuiltin('explode', $arguments),
                $arguments[1] ?? null
            ),
            'filter.gzuncompress' => $this->propagateFrom(
                $this->invokeBuiltin('gzuncompress', $arguments),
                $arguments[0] ?? null
            ),
            'filter.hex2bin' => $this->propagateFrom(
                $this->invokeBuiltin('hex2bin', $arguments),
                $arguments[0] ?? null
            ),
            'filter.html_entity_decode' => $this->propagateFrom(
                $this->invokeBuiltin('html_entity_decode', $arguments),
                $arguments[0] ?? null
            ),
            'filter.htmlspecialchars_decode' => $this->propagateFrom(
                $this->invokeBuiltin('htmlspecialchars_decode', $arguments),
                $arguments[0] ?? null
            ),
            'filter.implode' => $this->propagateIf(
                $this->invokeBuiltin('implode', $arguments),
                $this->backend->isTainted($arguments[0] ?? null, true) || $this->backend->isTainted($arguments[1] ?? null, true)
            ),
            'filter.join' => $this->propagateIf(
                $this->invokeBuiltin('join', $arguments),
                $this->backend->isTainted($arguments[0] ?? null, true) || $this->backend->isTainted($arguments[1] ?? null, true)
            ),
            'filter.json_decode' => $this->propagateFrom(
                $this->invokeBuiltin('json_decode', $arguments),
                $arguments[0] ?? null
            ),
            'filter.ltrim' => $this->propagateFrom(
                $this->invokeBuiltin('ltrim', $arguments),
                $arguments[0] ?? null
            ),
            'filter.pathinfo' => $this->propagateFrom(
                $this->invokeBuiltin('pathinfo', $arguments),
                $arguments[0] ?? null
            ),
            'filter.rawurldecode' => $this->propagateFrom(
                $this->invokeBuiltin('rawurldecode', $arguments),
                $arguments[0] ?? null
            ),
            'filter.rawurlencode' => $this->propagateFrom(
                $this->invokeBuiltin('rawurlencode', $arguments),
                $arguments[0] ?? null
            ),
            'filter.rtrim' => $this->propagateFrom(
                $this->invokeBuiltin('rtrim', $arguments),
                $arguments[0] ?? null
            ),
            'filter.sprintf' => $this->applySprintf($arguments),
            'filter.str_ireplace' => $this->applyStringReplace('str_ireplace', $arguments),
            'filter.str_pad' => $this->propagateFrom(
                $this->invokeBuiltin('str_pad', $arguments),
                $arguments[0] ?? null
            ),
            'filter.str_replace' => $this->applyStringReplace('str_replace', $arguments),
            'filter.strstr' => $this->propagateFrom(
                $this->invokeBuiltin('strstr', $arguments),
                $arguments[0] ?? null
            ),
            'filter.strtolower' => $this->propagateFrom(
                $this->invokeBuiltin('strtolower', $arguments),
                $arguments[0] ?? null
            ),
            'filter.strtoupper' => $this->propagateFrom(
                $this->invokeBuiltin('strtoupper', $arguments),
                $arguments[0] ?? null
            ),
            'filter.substr' => $this->propagateFrom(
                $this->invokeBuiltin('substr', $arguments),
                $arguments[0] ?? null
            ),
            'filter.trim' => $this->propagateFrom(
                $this->invokeBuiltin('trim', $arguments),
                $arguments[0] ?? null
            ),
            'filter.urldecode' => $this->propagateFrom(
                $this->invokeBuiltin('urldecode', $arguments),
                $arguments[0] ?? null
            ),
            'filter.urlencode' => $this->propagateFrom(
                $this->invokeBuiltin('urlencode', $arguments),
                $arguments[0] ?? null
            ),
            'filter.vsprintf' => $this->applyVsprintf($arguments),
            default => null,
        };
    }

    /**
     * @param array<int, mixed> $arguments
     */
    private function applySprintf(array $arguments): mixed
    {
        $result = $this->invokeBuiltin('sprintf', $arguments);
        $format = $arguments[0] ?? null;
        $args = array_slice($arguments, 1);
        $anyArgTainted = false;
        foreach ($args as $arg) {
            if ($this->backend->isTainted($arg, true)) {
                $anyArgTainted = true;
                break;
            }
        }

        return $this->propagateIf(
            $result,
            $this->backend->isTainted($format, true) || $anyArgTainted
        );
    }

    /**
     * @param array<int, mixed> $arguments
     */
    private function applyVsprintf(array $arguments): mixed
    {
        $result = $this->invokeBuiltin('vsprintf', $arguments);
        $format = $arguments[0] ?? null;
        $args = $arguments[1] ?? array();

        return $this->propagateIf(
            $result,
            $this->backend->isTainted($format, true) || $this->backend->isTainted($args, true)
        );
    }

    /**
     * @param array<int, mixed> $arguments
     */
    private function applyStringReplace(string $function, array $arguments): mixed
    {
        $callArgs = array_slice($arguments, 0, 3);
        $result = $this->invokeBuiltin($function, $callArgs);
        $replace = $arguments[1] ?? null;
        $subject = $arguments[2] ?? null;

        return $this->propagateIf(
            $result,
            $this->backend->isTainted($replace, true) || $this->backend->isTainted($subject, true)
        );
    }

    private function propagateFrom(mixed $result, mixed $source): mixed
    {
        return $this->propagateIf($result, $this->backend->isTainted($source, true));
    }

    private function propagateIf(mixed $result, bool $shouldPropagate): mixed
    {
        if (!$shouldPropagate) {
            return $result;
        }

        return $this->taintifyLikeLegacyXmark($result);
    }

    private function taintifyLikeLegacyXmark(mixed $value): mixed
    {
        if (is_string($value)) {
            return TaintedValue::tainted($value, 'filter.propagation');
        }

        if (is_array($value)) {
            $result = array();
            foreach ($value as $key => $inner) {
                $result[$key] = $this->taintifyLikeLegacyXmark($inner);
            }

            return $result;
        }

        // Legacy prvd_xmark only marks strings and recursively arrays of strings.
        return $value;
    }

    /**
     * @param array<int, mixed> $arguments
     */
    private function invokeBuiltin(string $function, array $arguments): mixed
    {
        $unwrapped = array();
        foreach ($arguments as $argument) {
            $unwrapped[] = $this->unwrap($argument);
        }

        // PHP 8.4 tightened json_decode() #2 to ?bool; older ecosystems may still
        // pass integer-like values that were previously coerced.
        if ($function === 'json_decode' && isset($unwrapped[1]) && is_int($unwrapped[1])) {
            $unwrapped[1] = (bool) $unwrapped[1];
        }

        return $function(...$unwrapped);
    }

    private function unwrap(mixed $value): mixed
    {
        if ($value instanceof TaintedValue) {
            return $value->value();
        }

        if (is_array($value)) {
            $result = array();
            foreach ($value as $key => $inner) {
                $result[$key] = $this->unwrap($inner);
            }

            return $result;
        }

        return $value;
    }
}
