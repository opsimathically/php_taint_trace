<?php

declare(strict_types=1);

namespace PhpTaintTrace\Runtime;

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

final class XxeRuntimeSlice
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
        $plan = $this->xxeHookPlan();
        $handlers = new HookHandlerRegistry(true);
        foreach ($plan->hooks() as $hook) {
            $hookId = $hook->id();
            $sinkName = $hook->target();

            $handlers->register($hookId, function ($context) use ($hookId, $sinkName): void {
                $arguments = $this->extractXmlArguments($hookId, $context->arguments());
                $this->runner->inspect($sinkName, SinkCategory::XXE, $arguments);
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

    private function xxeHookPlan(): BaselineHookPlan
    {
        $hooks = array_filter(
            LegacyBaselineHookPlanFactory::create()->hooks(),
            static fn (HookDefinition $hook): bool => str_starts_with($hook->id(), 'sink.xxe.')
                || str_starts_with($hook->id(), 'method.xxe.')
        );

        return new BaselineHookPlan(...array_values($hooks));
    }

    /**
     * @param array<int, mixed> $arguments
     * @return array<int, mixed>
     */
    private function extractXmlArguments(string $hookId, array $arguments): array
    {
        $normalizedHookId = strtolower($hookId);
        return match ($normalizedHookId) {
            'sink.xxe.simplexml_load_string',
            'sink.xxe.simplexml_load_file',
            'method.xxe.domdocument.load',
            'method.xxe.domdocument.loadxml',
            'method.xxe.xmlreader.open',
            'method.xxe.xmlreader.xml' => $this->takeArguments($arguments, array(0)),
            default => $arguments,
        };
    }

    /**
     * @param array<int, mixed> $arguments
     * @param int[] $indices
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
}
