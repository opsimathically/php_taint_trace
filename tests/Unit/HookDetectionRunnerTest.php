<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit;

use PhpTaintTrace\Detector\TaintInputDetector;
use PhpTaintTrace\Instrumentation\HookDefinition;
use PhpTaintTrace\Instrumentation\InstrumentationBackendInterface;
use PhpTaintTrace\Instrumentation\InstrumentationCapabilities;
use PhpTaintTrace\Model\SinkCategory;
use PhpTaintTrace\Runtime\HookCandidateStore;
use PhpTaintTrace\Runtime\DetectorPipeline;
use PhpTaintTrace\Runtime\HookDetectionRunner;
use PhpTaintTrace\Runtime\HookFindingStore;
use PhpTaintTrace\Verification\Detector\CandidateBuilder;
use PHPUnit\Framework\TestCase;

final class HookDetectionRunnerTest extends TestCase
{
    public function testRunnerWrapsBackendTaintedArgumentsForDetectorPipeline(): void
    {
        $backend = new class implements InstrumentationBackendInterface {
            public function backendName(): string
            {
                return 'test-backend';
            }

            public function capabilities(): InstrumentationCapabilities
            {
                return InstrumentationCapabilities::full();
            }

            public function registerHook(HookDefinition $hook, callable $handler): void
            {
            }

            public function markTainted(mixed &$value, bool $recursive = true, ?string $source = null): void
            {
            }

            public function isTainted(mixed $value, bool $recursive = true): bool
            {
                return $value === 'tainted';
            }
        };

        $runner = new HookDetectionRunner(
            new DetectorPipeline(new TaintInputDetector()),
            new HookFindingStore(),
            $backend
        );

        $findings = $runner->inspect('system', SinkCategory::RCE, array('tainted'));
        self::assertCount(1, $findings);
        self::assertSame('system', $findings[0]->sinkName());
    }

    public function testRunnerWithoutBackendPreservesCurrentTaintedValueOnlyBehavior(): void
    {
        $runner = new HookDetectionRunner(
            new DetectorPipeline(new TaintInputDetector()),
            new HookFindingStore()
        );

        $findings = $runner->inspect('system', SinkCategory::RCE, array('tainted'));
        self::assertCount(0, $findings);
    }

    public function testRunnerEmitsCandidateRecordsWithoutChangingFindings(): void
    {
        $candidateStore = new HookCandidateStore();
        $findingStore = new HookFindingStore();
        $runner = new HookDetectionRunner(
            new DetectorPipeline(new TaintInputDetector()),
            $findingStore,
            null,
            new CandidateBuilder(),
            $candidateStore
        );

        $findings = $runner->inspect(
            'system',
            SinkCategory::RCE,
            array(\PhpTaintTrace\Core\TaintedValue::tainted('id', '_GET'))
        );

        self::assertCount(1, $findings);
        self::assertCount(1, $findingStore->all());
        self::assertCount(1, $candidateStore->all());
        self::assertSame('system', $candidateStore->all()[0]->sinkName());
        self::assertSame('rce', $candidateStore->all()[0]->sinkCategory());
        $stacktrace = $candidateStore->all()[0]->sinkEvidence()->metadata()['stacktrace'] ?? array();
        self::assertIsArray($stacktrace);
        self::assertNotEmpty($stacktrace);
        self::assertSame(0, $stacktrace[0]['level'] ?? null);
    }
}
