<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit;

use PhpTaintTrace\Core\TaintedValue;
use PhpTaintTrace\Detector\PayloadKeywordDetector;
use PhpTaintTrace\Detector\TaintInputDetector;
use PhpTaintTrace\Instrumentation\Backend\ArrayInstrumentationBackend;
use PhpTaintTrace\Runtime\DetectorPipeline;
use PhpTaintTrace\Runtime\FileRuntimeSlice;
use PhpTaintTrace\Model\SinkCategory;
use PHPUnit\Framework\TestCase;

final class FileRuntimeSliceTest extends TestCase
{
    public function testBootstrapRegistersFileHooksOnly(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new FileRuntimeSlice($backend);

        $report = $slice->bootstrap();

        self::assertSame(24, $report->registeredCount());
        self::assertSame(0, $report->skippedCount());
        self::assertCount(24, $backend->hooks());
        self::assertArrayHasKey('sink.file.file_get_contents', $backend->hooks());
        self::assertArrayHasKey('sink.file.move_uploaded_file', $backend->hooks());
        self::assertArrayHasKey('sink.file.symlink', $backend->hooks());
        self::assertArrayHasKey('method.file.splfileobject.__construct', $backend->hooks());
        self::assertArrayNotHasKey('sink.ssrf.file_get_contents', $backend->hooks());
        self::assertArrayNotHasKey('sink.rce.system', $backend->hooks());
    }

    public function testSinglePathHookDispatchProducesFindings(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $pipeline = new DetectorPipeline(
            new TaintInputDetector(),
            new PayloadKeywordDetector('xtanzi')
        );
        $slice = new FileRuntimeSlice($backend, $pipeline);
        $slice->bootstrap();

        $backend->dispatchPreHook('sink.file.readfile', array(
            TaintedValue::tainted('/tmp/xtanzi.txt', 'query.file'),
        ));

        $findings = $slice->findings();
        self::assertCount(2, $findings);
        self::assertSame('readfile', $findings[0]->sinkName());
        self::assertSame('taint-input-detector', $findings[0]->detector());
        self::assertSame('payload-keyword-detector', $findings[1]->detector());
    }

    public function testCopyInspectsSourceAndDestinationPathArguments(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new FileRuntimeSlice($backend, new DetectorPipeline(new TaintInputDetector()));
        $slice->bootstrap();

        $backend->dispatchPreHook('sink.file.copy', array(
            'safe-source.txt',
            TaintedValue::tainted('tainted-dest.txt', 'query.dest'),
        ));

        $findings = $slice->findings();
        self::assertCount(1, $findings);
        self::assertSame('copy', $findings[0]->sinkName());
    }

    public function testMoveUploadedFileInspectsDestinationArgument(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new FileRuntimeSlice($backend, new DetectorPipeline(new TaintInputDetector()));
        $slice->bootstrap();

        $backend->dispatchPreHook('sink.file.move_uploaded_file', array(
            TaintedValue::tainted('ignored-source.tmp', 'query.tmp'),
            'safe-destination.txt',
        ));
        self::assertCount(0, $slice->findings());

        $backend->dispatchPreHook('sink.file.move_uploaded_file', array(
            'safe-source.tmp',
            TaintedValue::tainted('tainted-destination.txt', 'query.dest'),
        ));
        self::assertCount(1, $slice->findings());
        self::assertSame('move_uploaded_file', $slice->findings()[0]->sinkName());
    }

    public function testRemoteWrapperPathIsClassifiedAsSsrfCategory(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new FileRuntimeSlice(
            $backend,
            new DetectorPipeline(
                new TaintInputDetector(),
                new PayloadKeywordDetector('xtanzi')
            )
        );
        $slice->bootstrap();

        $backend->dispatchPreHook('sink.file.file_get_contents', array(
            TaintedValue::tainted('https://xtanzi.attacker.tld/path', 'query.path'),
        ));

        $findings = $slice->findings();
        self::assertCount(2, $findings);
        self::assertSame(SinkCategory::SSRF, $findings[0]->sinkCategory());
        self::assertSame(SinkCategory::SSRF, $findings[1]->sinkCategory());
    }

    public function testMixedRemoteAndLocalFileArgumentsAreClassifiedSeparately(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new FileRuntimeSlice($backend, new DetectorPipeline(new TaintInputDetector()));
        $slice->bootstrap();

        $backend->dispatchPreHook('sink.file.copy', array(
            TaintedValue::tainted('http://xtanzi.attacker.tld/file.txt', 'query.src'),
            TaintedValue::tainted('/tmp/local-copy.txt', 'query.dest'),
        ));

        $findings = $slice->findings();
        self::assertCount(2, $findings);
        self::assertSame(SinkCategory::FILE, $findings[0]->sinkCategory());
        self::assertSame(SinkCategory::SSRF, $findings[1]->sinkCategory());
    }

    public function testSplFileObjectConstructorMethodHookInspectsPathArgument(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new FileRuntimeSlice($backend, new DetectorPipeline(new TaintInputDetector()));
        $slice->bootstrap();

        $backend->dispatchPreHook('method.file.splfileobject.__construct', array(
            TaintedValue::tainted('/tmp/xtanzi.txt', 'query.path'),
            'r',
        ));

        $findings = $slice->findings();
        self::assertCount(1, $findings);
        self::assertSame('SplFileObject::__construct', $findings[0]->sinkName());
        self::assertSame(SinkCategory::FILE, $findings[0]->sinkCategory());
    }
}
