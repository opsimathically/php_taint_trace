<?php

declare(strict_types=1);

namespace PhpTaintTrace\Runtime;

use PhpTaintTrace\Core\TaintedValue;
use PhpTaintTrace\Detector\PayloadKeywordDetector;
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

final class RceRuntimeSlice
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
            $pipeline ?? new DetectorPipeline(
                new TaintInputDetector(),
                new PayloadKeywordDetector('xtanzi')
            ),
            $this->store,
            $this->backend,
            $this->emitCandidates ? new CandidateBuilder() : null,
            $this->candidateStore
        );
    }

    public function bootstrap(): InstrumentationBootstrapReport
    {
        $plan = $this->rceHookPlan();
        $handlers = new HookHandlerRegistry(true);
        foreach ($plan->hooks() as $hook) {
            $hookId = $hook->id();
            $sinkName = $hook->target();
            $argumentIndices = $this->sinkArgumentIndices($hookId);

            $handlers->register($hookId, function ($context) use ($hookId, $sinkName, $argumentIndices): void {
                $rawArguments = $context->arguments();
                $arguments = $this->selectArguments($rawArguments, $argumentIndices);
                $metadata = $this->extractRceMetadata($hookId, $rawArguments, $argumentIndices);
                $this->runner->inspect($sinkName, SinkCategory::RCE, $arguments, $metadata);
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

    private function rceHookPlan(): BaselineHookPlan
    {
        $hooks = array_filter(
            LegacyBaselineHookPlanFactory::create()->hooks(),
            static fn (HookDefinition $hook): bool => str_starts_with($hook->id(), 'sink.rce.')
        );

        return new BaselineHookPlan(...array_values($hooks));
    }

    /**
     * @return int[]
     */
    private function sinkArgumentIndices(string $hookId): array
    {
        return match ($hookId) {
            'sink.rce.dl',
            'sink.rce.exec',
            'sink.rce.expect_popen',
            'sink.rce.passthru',
            'sink.rce.pcntl_exec',
            'sink.rce.popen',
            'sink.rce.proc_open',
            'sink.rce.shell_exec',
            'sink.rce.system',
            'sink.rce.unserialize' => array(0),
            'sink.rce.mail' => array(4),
            default => array(),
        };
    }

    /**
     * @param array<int, mixed> $arguments
     * @param int[] $indices
     * @return array<int, mixed>
     */
    private function selectArguments(array $arguments, array $indices): array
    {
        if (count($indices) === 0) {
            return $arguments;
        }

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
     * @param int[] $indices
     * @return array<string, mixed>
     */
    private function extractRceMetadata(string $hookId, array $arguments, array $indices): array
    {
        if ($indices === array()) {
            return array();
        }

        $commandIndex = $indices[0];
        if (!array_key_exists($commandIndex, $arguments)) {
            return array();
        }

        $command = $this->normalizeRceValue($arguments[$commandIndex]);
        $rce = array(
            'hook_id' => $hookId,
            'argument_index' => $commandIndex,
        );
        if ($command !== null) {
            $rce['command'] = $command;
        }

        return array('rce' => $rce);
    }

    private function normalizeRceValue(mixed $value, int $depth = 0): mixed
    {
        if ($depth >= 8) {
            return '[depth_limit]';
        }

        if ($value instanceof TaintedValue) {
            return $this->normalizeRceValue($value->value(), $depth + 1);
        }

        if ($value === null || is_scalar($value)) {
            if (is_string($value)) {
                $trimmed = trim($value);
                return $trimmed === '' ? null : $value;
            }

            return $value;
        }

        if (is_array($value)) {
            $normalized = array();
            foreach ($value as $key => $entry) {
                $normalized[$key] = $this->normalizeRceValue($entry, $depth + 1);
            }

            return $normalized;
        }

        if ($value instanceof \Stringable) {
            return (string) $value;
        }

        if (is_object($value)) {
            return sprintf('[object:%s]', $value::class);
        }

        if (is_resource($value)) {
            return sprintf('[resource:%s]', get_resource_type($value));
        }

        return sprintf('[type:%s]', gettype($value));
    }
}
