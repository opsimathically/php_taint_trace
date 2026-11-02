<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit;

use PhpTaintTrace\Core\TaintedValue;
use PhpTaintTrace\Detector\PayloadKeywordDetector;
use PhpTaintTrace\Detector\TaintInputDetector;
use PhpTaintTrace\Instrumentation\Backend\ArrayInstrumentationBackend;
use PhpTaintTrace\Runtime\DetectorPipeline;
use PhpTaintTrace\Runtime\RceRuntimeSlice;
use PHPUnit\Framework\TestCase;

final class RceRuntimeSliceTest extends TestCase
{
    public function testBootstrapRegistersRceHooksOnly(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new RceRuntimeSlice($backend);

        $report = $slice->bootstrap();

        self::assertSame(11, $report->registeredCount());
        self::assertSame(0, $report->skippedCount());
        self::assertCount(11, $backend->hooks());
        self::assertArrayHasKey('sink.rce.exec', $backend->hooks());
        self::assertArrayHasKey('sink.rce.unserialize', $backend->hooks());
        self::assertArrayHasKey('sink.rce.mail', $backend->hooks());
        self::assertArrayHasKey('sink.rce.pcntl_exec', $backend->hooks());
        self::assertArrayNotHasKey('sink.sqli.pg_query', $backend->hooks());
    }

    public function testRceHookDispatchProducesFindingsThroughDetectorPipeline(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $pipeline = new DetectorPipeline(
            new TaintInputDetector(),
            new PayloadKeywordDetector('xtanzi')
        );
        $slice = new RceRuntimeSlice($backend, $pipeline);
        $slice->bootstrap();

        $backend->dispatchPreHook('sink.rce.system', array(
            TaintedValue::tainted('id xtanzi', 'query.cmd'),
            0,
        ));

        $findings = $slice->findings();
        self::assertCount(2, $findings);
        self::assertSame('system', $findings[0]->sinkName());
        self::assertSame('taint-input-detector', $findings[0]->detector());
        self::assertSame('payload-keyword-detector', $findings[1]->detector());
    }

    public function testRceHookUsesFirstArgumentAsSinkInputLikeLegacyWrappers(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new RceRuntimeSlice($backend, new DetectorPipeline(new TaintInputDetector()));
        $slice->bootstrap();

        // Legacy RCE wrappers check the command/payload argument (first parameter).
        $backend->dispatchPreHook('sink.rce.exec', array(
            'safe-command',
            TaintedValue::tainted('secondary-taint', 'query.other'),
        ));
        self::assertCount(0, $slice->findings());

        $backend->dispatchPreHook('sink.rce.exec', array(
            TaintedValue::tainted('id', 'query.cmd'),
            array(),
        ));
        self::assertCount(1, $slice->findings());
        self::assertSame('exec', $slice->findings()[0]->sinkName());
    }

    public function testUnserializeHookProducesPayloadFindingForSerializedKeywordInput(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new RceRuntimeSlice(
            $backend,
            new DetectorPipeline(
                new TaintInputDetector(),
                new PayloadKeywordDetector('xtanzi')
            )
        );
        $slice->bootstrap();

        $backend->dispatchPreHook('sink.rce.unserialize', array(
            'a:1:{s:1:"k";s:6:"xtanzi";}',
        ));

        $findings = $slice->findings();
        self::assertCount(1, $findings);
        self::assertSame('unserialize', $findings[0]->sinkName());
        self::assertSame('payload-keyword-detector', $findings[0]->detector());
    }

    public function testMailHookInspectsOnlyFifthArgument(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new RceRuntimeSlice($backend, new DetectorPipeline(new TaintInputDetector()));
        $slice->bootstrap();

        $backend->dispatchPreHook('sink.rce.mail', array(
            'admin@example.test',
            TaintedValue::tainted('tainted-subject', 'query.subject'),
            'body',
            '',
            '',
        ));
        self::assertCount(0, $slice->findings());

        $backend->dispatchPreHook('sink.rce.mail', array(
            'admin@example.test',
            'subject',
            'body',
            '',
            TaintedValue::tainted('-X /tmp/evil', 'query.additional_parameters'),
        ));
        self::assertCount(1, $slice->findings());
        self::assertSame('mail', $slice->findings()[0]->sinkName());
    }

    public function testPcntlExecHookInspectsProgramArgument(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new RceRuntimeSlice($backend, new DetectorPipeline(new TaintInputDetector()));
        $slice->bootstrap();

        $backend->dispatchPreHook('sink.rce.pcntl_exec', array(
            TaintedValue::tainted('/tmp/xtanzi-bin', 'query.bin'),
            array('arg1'),
            array(),
        ));

        self::assertCount(1, $slice->findings());
        self::assertSame('pcntl_exec', $slice->findings()[0]->sinkName());
    }

    public function testExecHookCapturesCommandInCandidateMetadata(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new RceRuntimeSlice(
            $backend,
            new DetectorPipeline(new TaintInputDetector()),
            emitCandidates: true
        );
        $slice->bootstrap();

        $backend->dispatchPreHook('sink.rce.exec', array(
            TaintedValue::tainted('cat /etc/passwd', 'query.cmd'),
        ));

        $candidates = $slice->candidates();
        self::assertCount(1, $candidates);
        $rceMetadata = $candidates[0]->sinkEvidence()->metadata()['rce'] ?? null;
        self::assertIsArray($rceMetadata);
        self::assertSame('sink.rce.exec', $rceMetadata['hook_id'] ?? null);
        self::assertSame(0, $rceMetadata['argument_index'] ?? null);
        self::assertSame('cat /etc/passwd', $rceMetadata['command'] ?? null);
    }
}
