<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit;

use PhpTaintTrace\Core\TaintedValue;
use PhpTaintTrace\Instrumentation\Backend\ArrayInstrumentationBackend;
use PhpTaintTrace\Runtime\BaselineRuntime;
use PHPUnit\Framework\TestCase;

final class BaselineRuntimeRequestLifecycleTest extends TestCase
{
    public function testStartRequestBootstrapsAndSeedsTaintSources(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $runtime = new BaselineRuntime($backend);

        $get = array('id' => '1');
        $post = array('name' => 'alice');
        $cookie = array('sid' => 'abc');
        $files = array('upload' => array('name' => 'x.txt'));
        $request = array('id' => '1', 'name' => 'alice');
        $server = array(
            'HTTP_HOST' => 'example.test',
            'HTTP_X_API_TOKEN' => 'token',
            'REQUEST_METHOD' => 'GET',
        );

        $report = $runtime->startRequest($get, $post, $cookie, $files, $request, $server);

        self::assertTrue($runtime->hasBootstrapped());
        self::assertTrue($report->bootstrappedNow());
        self::assertSame(130, $report->bootstrapReport()->registeredCount());
        self::assertSame(7, $report->seededSourceCount());
        self::assertSame(
            array(
                '_GET',
                '_POST',
                '_COOKIE',
                '_FILES',
                '_REQUEST',
                '_SERVER[HTTP_HOST]',
                '_SERVER[HTTP_X_API_TOKEN]',
            ),
            $report->seededSources()
        );
        self::assertCount(130, $backend->hooks());
        self::assertCount(7, $backend->marks());
    }

    public function testStartRequestReusesExistingBootstrapAndClearsFindings(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $runtime = new BaselineRuntime($backend, true, 'full', true);
        $runtime->bootstrap();

        $backend->dispatchPreHook('sink.rce.system', array(
            TaintedValue::tainted('id', 'query.cmd'),
        ));
        self::assertCount(1, $runtime->findings());
        self::assertCount(1, $runtime->candidates());

        $get = array();
        $post = array();
        $cookie = array();
        $files = array();
        $request = array();
        $server = array();
        $report = $runtime->startRequest($get, $post, $cookie, $files, $request, $server);

        self::assertFalse($report->bootstrappedNow());
        self::assertCount(0, $runtime->findings());
        self::assertCount(0, $runtime->candidates());
        self::assertCount(5, $backend->marks());
    }

    public function testBootstrapIsIdempotent(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $runtime = new BaselineRuntime($backend);

        $first = $runtime->bootstrap();
        $second = $runtime->bootstrap();

        self::assertSame($first, $second);
        self::assertCount(130, $backend->hooks());
    }
}
