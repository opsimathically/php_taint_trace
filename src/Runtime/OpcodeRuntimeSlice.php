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

final class OpcodeRuntimeSlice
{
    public const HOOK_PROFILE_FULL = 'full';
    public const HOOK_PROFILE_SAFE = 'safe';

    /**
     * @var string[]
     */
    private const SAFE_PROFILE_HOOK_IDS = array(
        'opcode.echo',
        'opcode.exit',
        'opcode.include_or_eval',
        'opcode.init_dynamic_call',
    );

    private readonly HookFindingStore $store;
    private readonly HookCandidateStore $candidateStore;
    private readonly HookDetectionRunner $rceRunner;
    private readonly HookDetectionRunner $xssRunner;

    public function __construct(
        private readonly InstrumentationBackendInterface $backend,
        ?DetectorPipeline $rcePipeline = null,
        ?DetectorPipeline $xssPipeline = null,
        private readonly bool $emitCandidates = false,
        private readonly string $hookProfile = self::HOOK_PROFILE_FULL
    ) {
        $this->store = new HookFindingStore();
        $this->candidateStore = new HookCandidateStore();
        $this->rceRunner = new HookDetectionRunner(
            $rcePipeline ?? new DetectorPipeline(
                new TaintInputDetector(),
                new PayloadKeywordDetector('xtanzi')
            ),
            $this->store,
            $this->backend,
            $this->emitCandidates ? new CandidateBuilder() : null,
            $this->candidateStore
        );
        $this->xssRunner = new HookDetectionRunner(
            $xssPipeline ?? new DetectorPipeline(new TaintInputDetector()),
            $this->store,
            $this->backend,
            $this->emitCandidates ? new CandidateBuilder() : null,
            $this->candidateStore
        );
    }

    public function bootstrap(): InstrumentationBootstrapReport
    {
        $handlers = new HookHandlerRegistry(true);
        foreach ($this->opcodeHookPlan()->hooks() as $hook) {
            $hookId = $hook->id();

            $handlers->register($hookId, function ($context) use ($hookId) {
                return $this->handleOpcode($hookId, $context->arguments());
            });
        }

        $bootstrap = new RuntimeInstrumentationBootstrap($this->backend);
        return $bootstrap->bootstrap($this->opcodeHookPlan(), $handlers);
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

    private function opcodeHookPlan(): BaselineHookPlan
    {
        $hooks = array_filter(
            LegacyBaselineHookPlanFactory::create()->hooks(),
            fn (HookDefinition $hook): bool => str_starts_with($hook->id(), 'opcode.') &&
                $this->isHookEnabledForProfile($hook->id())
        );

        return new BaselineHookPlan(...array_values($hooks));
    }

    private function isHookEnabledForProfile(string $hookId): bool
    {
        if ($this->hookProfile === self::HOOK_PROFILE_FULL) {
            return true;
        }

        if ($this->hookProfile === self::HOOK_PROFILE_SAFE) {
            return in_array($hookId, self::SAFE_PROFILE_HOOK_IDS, true);
        }

        return true;
    }

    /**
     * @param array<int, mixed> $arguments
     */
    private function handleOpcode(string $hookId, array $arguments): mixed
    {
        return match ($hookId) {
            'opcode.assign_concat',
            'opcode.concat',
            'opcode.fast_concat' => $this->buildConcatResult($arguments),
            'opcode.rope_end' => $this->buildRopeEndResult($arguments),
            'opcode.do_fcall',
            'opcode.do_fcall_by_name',
            'opcode.do_icall',
            'opcode.do_ucall',
            'opcode.init_dynamic_call',
            'opcode.init_method_call',
            'opcode.init_user_call',
            'opcode.include_or_eval' => $this->inspectRceOpcode($hookId, $arguments),
            'opcode.echo',
            'opcode.exit' => $this->inspectXssOpcode($hookId, $arguments),
            default => null,
        };
    }

    /**
     * @param array<int, mixed> $arguments
     */
    private function inspectRceOpcode(string $hookId, array $arguments): null
    {
        $sinkName = $this->opcodeSinkName($hookId);
        $selected = match ($hookId) {
            'opcode.do_fcall',
            'opcode.do_fcall_by_name',
            'opcode.do_icall',
            'opcode.do_ucall' => $this->takeArguments($arguments, array(0, 1)),
            default => $this->takeArguments($arguments, array(0)),
        };

        $this->rceRunner->inspect($sinkName, SinkCategory::RCE, $selected);
        return null;
    }

    /**
     * @param array<int, mixed> $arguments
     */
    private function inspectXssOpcode(string $hookId, array $arguments): null
    {
        $sinkName = $this->opcodeSinkName($hookId);
        $selected = $this->takeArguments($arguments, array(0));

        $this->xssRunner->inspect($sinkName, SinkCategory::XSS, $selected);
        return null;
    }

    /**
     * @param array<int, mixed> $arguments
     */
    private function buildConcatResult(array $arguments): mixed
    {
        $left = $arguments[0] ?? '';
        $right = $arguments[1] ?? '';

        $result = (string) $this->unwrap($left) . (string) $this->unwrap($right);
        if ($this->backend->isTainted($left, true) || $this->backend->isTainted($right, true)) {
            return TaintedValue::tainted($result, 'opcode.concat');
        }

        return $result;
    }

    /**
     * @param array<int, mixed> $arguments
     */
    private function buildRopeEndResult(array $arguments): mixed
    {
        $parts = $arguments[0] ?? array();
        if (!is_array($parts)) {
            $parts = array($parts);
        }

        $rendered = array();
        foreach ($parts as $part) {
            $rendered[] = (string) $this->unwrap($part);
        }

        $result = implode('', $rendered);
        if ($this->backend->isTainted($parts, true)) {
            return TaintedValue::tainted($result, 'opcode.rope_end');
        }

        return $result;
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

    private function opcodeSinkName(string $hookId): string
    {
        return (string) preg_replace('/^opcode\./', '', $hookId);
    }

    private function unwrap(mixed $value): mixed
    {
        if ($value instanceof TaintedValue) {
            return $value->value();
        }

        return $value;
    }
}
