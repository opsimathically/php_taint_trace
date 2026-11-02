<?php

declare(strict_types=1);

namespace PhpTaintTrace\Runtime;

use PhpTaintTrace\Core\TaintedValue;
use PhpTaintTrace\Detector\TaintInputDetector;
use PhpTaintTrace\Instrumentation\BaselineHookPlan;
use PhpTaintTrace\Instrumentation\HookDefinition;
use PhpTaintTrace\Instrumentation\HookHandlerRegistry;
use PhpTaintTrace\Instrumentation\InstrumentationBackendInterface;
use PhpTaintTrace\Instrumentation\InstrumentationBootstrapReport;
use PhpTaintTrace\Instrumentation\LegacyBaselineHookPlanFactory;
use PhpTaintTrace\Instrumentation\RequestTaintSeeder;
use PhpTaintTrace\Instrumentation\RuntimeInstrumentationBootstrap;
use PhpTaintTrace\Model\Finding;
use PhpTaintTrace\Model\SinkCategory;
use PhpTaintTrace\Verification\Detector\CandidateBuilder;
use PhpTaintTrace\Verification\Model\DetectorCandidate;

final class XssRuntimeSlice
{
    private readonly HookFindingStore $store;
    private readonly HookCandidateStore $candidateStore;
    private readonly HookDetectionRunner $runner;

    public function __construct(
        private readonly InstrumentationBackendInterface $backend,
        ?DetectorPipeline $pipeline = null,
        private readonly bool $emitCandidates = false
    ) {
        $this->store = new HookFindingStore();
        $this->candidateStore = new HookCandidateStore();
        $this->runner = new HookDetectionRunner(
            $pipeline ?? new DetectorPipeline(new TaintInputDetector()),
            $this->store,
            $this->backend,
            $this->emitCandidates ? new CandidateBuilder() : null,
            $this->candidateStore
        );
    }

    public function bootstrap(): InstrumentationBootstrapReport
    {
        $plan = $this->xssHookPlan();
        $handlers = new HookHandlerRegistry(true);
        foreach ($plan->hooks() as $hook) {
            $hookId = $hook->id();
            $sinkName = $hook->target();

            $handlers->register($hookId, function ($context) use ($hookId, $sinkName): void {
                $arguments = $this->extractXssArguments($hookId, $context->arguments());
                $this->runner->inspect($sinkName, SinkCategory::XSS, $arguments);
            });
        }

        $bootstrap = new RuntimeInstrumentationBootstrap($this->backend);
        return $bootstrap->bootstrap($plan, $handlers);
    }

    public function requestTaintSeeder(): RequestTaintSeeder
    {
        return new RequestTaintSeeder($this->backend);
    }

    /**
     * @return Finding[]
     */
    public function findings(): array
    {
        return $this->store->all();
    }

    public function clearFindings(): void
    {
        $this->store->clear();
    }

    /**
     * @return DetectorCandidate[]
     */
    public function candidates(): array
    {
        return $this->candidateStore->all();
    }

    public function clearCandidates(): void
    {
        $this->candidateStore->clear();
    }

    private function xssHookPlan(): BaselineHookPlan
    {
        $hooks = array_filter(
            LegacyBaselineHookPlanFactory::create()->hooks(),
            static fn (HookDefinition $hook): bool => str_starts_with($hook->id(), 'sink.xss.')
        );

        return new BaselineHookPlan(...array_values($hooks));
    }

    /**
     * @param array<int, mixed> $arguments
     * @return array<int, mixed>
     */
    private function extractXssArguments(string $hookId, array $arguments): array
    {
        return match ($hookId) {
            'sink.xss.print_r' => $this->takeArguments($arguments, array(0)),
            'sink.xss.printf' => array($this->buildPrintfLikeArgument($arguments)),
            'sink.xss.vprintf' => array($this->buildVprintfLikeArgument($arguments)),
            default => $arguments,
        };
    }

    /**
     * @param array<int, mixed> $arguments
     * @return array<int, mixed>
     */
    private function takeArguments(array $arguments, array $indices): array
    {
        $result = array();
        foreach ($indices as $index) {
            if (array_key_exists($index, $arguments)) {
                $result[] = $arguments[$index];
            }
        }

        return $result;
    }

    /**
     * @param array<int, mixed> $arguments
     */
    private function buildPrintfLikeArgument(array $arguments): mixed
    {
        $format = $arguments[0] ?? '';
        $formatRaw = (string) $this->unwrap($format);
        $originalArgs = array_slice($arguments, 1);

        $printfArgs = array();
        foreach ($originalArgs as $argument) {
            $printfArgs[] = $this->unwrap($argument);
        }

        $rendered = @sprintf($formatRaw, ...$printfArgs);
        if (!is_string($rendered)) {
            $rendered = $formatRaw;
        }

        $tainted = $this->backend->isTainted($format, true) || $this->backend->isTainted($originalArgs, true);
        if ($tainted) {
            return TaintedValue::tainted($rendered, 'xss.printf');
        }

        return $rendered;
    }

    /**
     * @param array<int, mixed> $arguments
     */
    private function buildVprintfLikeArgument(array $arguments): mixed
    {
        $format = $arguments[0] ?? '';
        $values = $arguments[1] ?? array();
        if (!is_array($values)) {
            $values = array($values);
        }

        $formatRaw = (string) $this->unwrap($format);
        $valueRaw = $this->unwrap($values);
        if (!is_array($valueRaw)) {
            $valueRaw = array($valueRaw);
        }

        $rendered = @vsprintf($formatRaw, $valueRaw);
        if (!is_string($rendered)) {
            $rendered = $formatRaw;
        }

        $tainted = $this->backend->isTainted($format, true) || $this->backend->isTainted($values, true);
        if ($tainted) {
            return TaintedValue::tainted($rendered, 'xss.vprintf');
        }

        return $rendered;
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
