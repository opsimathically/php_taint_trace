<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit;

use PhpTaintTrace\Core\TaintedValue;
use PhpTaintTrace\Detector\PayloadKeywordDetector;
use PhpTaintTrace\Detector\TaintInputDetector;
use PhpTaintTrace\Instrumentation\Backend\ArrayInstrumentationBackend;
use PhpTaintTrace\Runtime\DetectorPipeline;
use PhpTaintTrace\Runtime\SsrfRuntimeSlice;
use PHPUnit\Framework\TestCase;

final class SsrfRuntimeSliceTest extends TestCase
{
    public function testBootstrapRegistersSsrfSinkAndAuxTrackingHooks(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new SsrfRuntimeSlice($backend);

        $report = $slice->bootstrap();

        self::assertSame(13, $report->registeredCount());
        self::assertSame(0, $report->skippedCount());
        self::assertCount(13, $backend->hooks());
        self::assertArrayHasKey('sink.ssrf.file_get_contents', $backend->hooks());
        self::assertArrayHasKey('sink.ssrf.curl_exec', $backend->hooks());
        self::assertArrayHasKey('sink.ssrf.curl_multi_exec', $backend->hooks());
        self::assertArrayHasKey('sink.ssrf.fsockopen', $backend->hooks());
        self::assertArrayHasKey('sink.ssrf.get_headers', $backend->hooks());
        self::assertArrayHasKey('sink.ssrf.pfsockopen', $backend->hooks());
        self::assertArrayHasKey('sink.ssrf.stream_socket_client', $backend->hooks());
        self::assertArrayHasKey('method.ssrf.soapclient.__construct', $backend->hooks());
        self::assertArrayHasKey('method.ssrf.soapclient.__setLocation', $backend->hooks());
        self::assertArrayHasKey('aux.ssrf.curl_init', $backend->hooks());
        self::assertArrayHasKey('aux.ssrf.curl_setopt', $backend->hooks());
        self::assertArrayHasKey('aux.ssrf.curl_setopt_array', $backend->hooks());
        self::assertArrayHasKey('aux.ssrf.curl_multi_add_handle', $backend->hooks());
        self::assertArrayNotHasKey('sink.file.file_get_contents', $backend->hooks());
        self::assertArrayNotHasKey('sink.rce.system', $backend->hooks());
    }

    public function testFileGetContentsHookDispatchProducesFindings(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $pipeline = new DetectorPipeline(
            new TaintInputDetector(),
            new PayloadKeywordDetector('xtanzi')
        );
        $slice = new SsrfRuntimeSlice($backend, $pipeline);
        $slice->bootstrap();

        $backend->dispatchPreHook('sink.ssrf.file_get_contents', array(
            TaintedValue::tainted('http://xtanzi.example.test', 'query.url'),
        ));

        $findings = $slice->findings();
        self::assertCount(2, $findings);
        self::assertSame('file_get_contents', $findings[0]->sinkName());
        self::assertSame('taint-input-detector', $findings[0]->detector());
        self::assertSame('payload-keyword-detector', $findings[1]->detector());
    }

    public function testCurlExecWithoutTrackedUrlProducesNoFindings(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new SsrfRuntimeSlice($backend, new DetectorPipeline(new TaintInputDetector()));
        $slice->bootstrap();

        $backend->dispatchPreHook('sink.ssrf.curl_exec', array(
            TaintedValue::tainted('tainted-curl-handle-representation', 'query.url'),
        ));

        self::assertCount(0, $slice->findings());
    }

    public function testCurlExecUsesTrackedUrlFromCurlSetopt(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new SsrfRuntimeSlice(
            $backend,
            new DetectorPipeline(
                new TaintInputDetector(),
                new PayloadKeywordDetector('xtanzi')
            )
        );
        $slice->bootstrap();

        $handle = new \stdClass();
        $backend->dispatchPreHook('aux.ssrf.curl_setopt', array(
            $handle,
            defined('CURLOPT_URL') ? constant('CURLOPT_URL') : 10002,
            TaintedValue::tainted('http://xtanzi.example.test', 'query.url'),
        ));
        $backend->dispatchPreHook('sink.ssrf.curl_exec', array($handle));

        $findings = $slice->findings();
        self::assertCount(2, $findings);
        self::assertSame('curl_exec', $findings[0]->sinkName());
        self::assertSame('taint-input-detector', $findings[0]->detector());
        self::assertSame('payload-keyword-detector', $findings[1]->detector());
    }

    public function testCurlExecPayloadDetectionUsesEffectiveUrlMetadata(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new SsrfRuntimeSlice(
            $backend,
            new DetectorPipeline(new PayloadKeywordDetector('xtanzi'))
        );
        $slice->bootstrap();

        $backend->dispatchPreHook(
            'sink.ssrf.curl_exec',
            array(new \stdClass()),
            array('effective_url' => 'http://xtanzi.attacker.tld/resource')
        );

        $findings = $slice->findings();
        self::assertCount(1, $findings);
        self::assertSame('curl_exec', $findings[0]->sinkName());
        self::assertSame('payload-keyword-detector', $findings[0]->detector());
    }

    public function testCurlMultiExecUsesTrackedUrlsFromAddedHandles(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new SsrfRuntimeSlice(
            $backend,
            new DetectorPipeline(
                new TaintInputDetector(),
                new PayloadKeywordDetector('xtanzi')
            )
        );
        $slice->bootstrap();

        $easyHandle = new \stdClass();
        $multiHandle = new \stdClass();
        $backend->dispatchPreHook('aux.ssrf.curl_setopt', array(
            $easyHandle,
            defined('CURLOPT_URL') ? constant('CURLOPT_URL') : 10002,
            TaintedValue::tainted('http://xtanzi.example.test', 'query.url'),
        ));
        $backend->dispatchPreHook('aux.ssrf.curl_multi_add_handle', array(
            $multiHandle,
            $easyHandle,
        ));
        $backend->dispatchPreHook('sink.ssrf.curl_multi_exec', array(
            $multiHandle,
            0,
        ));

        $findings = $slice->findings();
        self::assertCount(2, $findings);
        self::assertSame('curl_multi_exec', $findings[0]->sinkName());
        self::assertSame('taint-input-detector', $findings[0]->detector());
        self::assertSame('payload-keyword-detector', $findings[1]->detector());
    }

    public function testAdditionalSsrfNetworkHooksUsePrimaryTargetArgument(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new SsrfRuntimeSlice(
            $backend,
            new DetectorPipeline(new TaintInputDetector())
        );
        $slice->bootstrap();

        $backend->dispatchPreHook('sink.ssrf.pfsockopen', array(
            TaintedValue::tainted('xtanzi.attacker.tld', 'query.host'),
            80,
        ));
        $backend->dispatchPreHook('sink.ssrf.fsockopen', array(
            TaintedValue::tainted('xtanzi.attacker.tld', 'query.host'),
            80,
        ));
        $backend->dispatchPreHook('sink.ssrf.get_headers', array(
            TaintedValue::tainted('http://xtanzi.attacker.tld', 'query.url'),
            true,
        ));
        $backend->dispatchPreHook('sink.ssrf.stream_socket_client', array(
            TaintedValue::tainted('tcp://xtanzi.attacker.tld:80', 'query.target'),
        ));
        $backend->dispatchPreHook('method.ssrf.soapclient.__construct', array(
            TaintedValue::tainted('http://xtanzi.attacker.tld/wsdl', 'query.wsdl'),
            array(),
        ));
        $backend->dispatchPreHook('method.ssrf.soapclient.__construct', array(
            null,
            array(
                'location' => TaintedValue::tainted('http://xtanzi.attacker.tld/soap', 'query.location'),
                'uri' => 'urn:ptt:local',
            ),
        ));
        $backend->dispatchPreHook('method.ssrf.soapclient.__setLocation', array(
            TaintedValue::tainted('http://xtanzi.attacker.tld/soap-via-setlocation', 'query.location'),
        ));

        $findings = $slice->findings();
        self::assertCount(7, $findings);
        self::assertSame('pfsockopen', $findings[0]->sinkName());
        self::assertSame('fsockopen', $findings[1]->sinkName());
        self::assertSame('get_headers', $findings[2]->sinkName());
        self::assertSame('stream_socket_client', $findings[3]->sinkName());
        self::assertSame('SoapClient::__construct', $findings[4]->sinkName());
        self::assertSame('SoapClient::__construct', $findings[5]->sinkName());
        self::assertSame('SoapClient::__setLocation', $findings[6]->sinkName());
    }
}
