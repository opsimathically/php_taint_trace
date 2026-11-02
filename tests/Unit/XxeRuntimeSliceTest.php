<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit;

use PhpTaintTrace\Core\TaintedValue;
use PhpTaintTrace\Detector\PayloadKeywordDetector;
use PhpTaintTrace\Detector\TaintInputDetector;
use PhpTaintTrace\Instrumentation\Backend\ArrayInstrumentationBackend;
use PhpTaintTrace\Runtime\DetectorPipeline;
use PhpTaintTrace\Runtime\XxeRuntimeSlice;
use PHPUnit\Framework\TestCase;

final class XxeRuntimeSliceTest extends TestCase
{
    public function testBootstrapRegistersXxeFunctionAndMethodHooks(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new XxeRuntimeSlice($backend);

        $report = $slice->bootstrap();

        self::assertSame(6, $report->registeredCount());
        self::assertSame(0, $report->skippedCount());
        self::assertCount(6, $backend->hooks());
        self::assertArrayHasKey('sink.xxe.simplexml_load_string', $backend->hooks());
        self::assertArrayHasKey('sink.xxe.simplexml_load_file', $backend->hooks());
        self::assertArrayHasKey('method.xxe.domdocument.load', $backend->hooks());
        self::assertArrayHasKey('method.xxe.domdocument.loadXML', $backend->hooks());
        self::assertArrayHasKey('method.xxe.xmlreader.open', $backend->hooks());
        self::assertArrayHasKey('method.xxe.xmlreader.XML', $backend->hooks());
        self::assertArrayNotHasKey('sink.rce.system', $backend->hooks());
        self::assertArrayNotHasKey('sink.xss.printf', $backend->hooks());
    }

    public function testSimplexmlLoadStringHookDispatchProducesFindings(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $pipeline = new DetectorPipeline(
            new TaintInputDetector(),
            new PayloadKeywordDetector('xtanzi')
        );
        $slice = new XxeRuntimeSlice($backend, $pipeline);
        $slice->bootstrap();

        $backend->dispatchPreHook('sink.xxe.simplexml_load_string', array(
            TaintedValue::tainted('<root>xtanzi</root>', 'query.xml'),
        ));

        $findings = $slice->findings();
        self::assertCount(2, $findings);
        self::assertSame('simplexml_load_string', $findings[0]->sinkName());
        self::assertSame('taint-input-detector', $findings[0]->detector());
        self::assertSame('payload-keyword-detector', $findings[1]->detector());
    }

    public function testDomAndXmlReaderMethodHooksUsePrimaryXmlArgument(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new XxeRuntimeSlice(
            $backend,
            new DetectorPipeline(new TaintInputDetector())
        );
        $slice->bootstrap();

        $backend->dispatchPreHook('method.xxe.domdocument.load', array(
            TaintedValue::tainted('/tmp/evil.xml', 'query.xmlpath'),
            0,
            array(),
        ));
        $backend->dispatchPreHook('method.xxe.domdocument.loadXML', array(
            TaintedValue::tainted('<root>dom</root>', 'query.xml'),
            0,
        ));
        $backend->dispatchPreHook('method.xxe.xmlreader.open', array(
            TaintedValue::tainted('http://attacker/evil.xml', 'query.xml'),
            null,
            0,
        ));
        $backend->dispatchPreHook('method.xxe.xmlreader.XML', array(
            TaintedValue::tainted('<root>reader</root>', 'query.xml'),
        ));

        $findings = $slice->findings();
        self::assertCount(4, $findings);
        self::assertSame('DOMDocument::load', $findings[0]->sinkName());
        self::assertSame('DOMDocument::loadXML', $findings[1]->sinkName());
        self::assertSame('XMLReader::open', $findings[2]->sinkName());
        self::assertSame('XMLReader::XML', $findings[3]->sinkName());
    }
}
