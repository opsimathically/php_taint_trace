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

final class FileRuntimeSlice
{
    private readonly PathSchemeClassifier $pathSchemeClassifier;
    private readonly HookFindingStore $store;
    private readonly HookCandidateStore $candidateStore;
    private readonly HookDetectionRunner $runner;

    public function __construct(
        private readonly InstrumentationBackendInterface $backend,
        ?DetectorPipeline $pipeline = null,
        private readonly bool $emitCandidates = false
    ) {
        $this->pathSchemeClassifier = new PathSchemeClassifier();
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
        $plan = $this->fileHookPlan();
        $handlers = new HookHandlerRegistry(true);
        foreach ($plan->hooks() as $hook) {
            $hookId = $hook->id();
            $sinkName = $hook->target();

            $handlers->register($hookId, function ($context) use ($hookId, $sinkName): void {
                $arguments = $this->extractPathArguments($hookId, $context->arguments());
                $classifiedArguments = $this->classifyPathArguments($arguments);
                if ($classifiedArguments['file'] !== array()) {
                    $this->runner->inspect($sinkName, SinkCategory::FILE, $classifiedArguments['file']);
                }
                if ($classifiedArguments['ssrf'] !== array()) {
                    $this->runner->inspect($sinkName, SinkCategory::SSRF, $classifiedArguments['ssrf']);
                }
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

    private function fileHookPlan(): BaselineHookPlan
    {
        $hooks = array_filter(
            LegacyBaselineHookPlanFactory::create()->hooks(),
            static fn (HookDefinition $hook): bool => str_starts_with($hook->id(), 'sink.file.')
                || str_starts_with($hook->id(), 'method.file.')
        );

        return new BaselineHookPlan(...array_values($hooks));
    }

    /**
     * @param array<int, mixed> $arguments
     * @return array<int, mixed>
     */
    private function extractPathArguments(string $hookId, array $arguments): array
    {
        return match ($hookId) {
            'sink.file.copy',
            'sink.file.link',
            'sink.file.rename',
            'sink.file.symlink' => $this->takeArguments($arguments, array(0, 1)),
            'sink.file.move_uploaded_file' => $this->takeArguments($arguments, array(1)),
            default => $this->takeArguments($arguments, array(0)),
        };
    }

    /**
     * @param array<int, mixed> $arguments
     * @return array{file: array<int, mixed>, ssrf: array<int, mixed>}
     */
    private function classifyPathArguments(array $arguments): array
    {
        $fileArguments = array();
        $ssrfArguments = array();

        foreach ($arguments as $argument) {
            if ($this->pathSchemeClassifier->isRemoteWrapper($argument)) {
                $ssrfArguments[] = $argument;
                continue;
            }

            $fileArguments[] = $argument;
        }

        return array(
            'file' => $fileArguments,
            'ssrf' => $ssrfArguments,
        );
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
