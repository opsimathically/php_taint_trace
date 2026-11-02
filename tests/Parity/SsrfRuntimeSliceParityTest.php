<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Parity;

use PhpTaintTrace\Core\TaintedValue;
use PhpTaintTrace\Instrumentation\Backend\ArrayInstrumentationBackend;
use PhpTaintTrace\Runtime\SsrfRuntimeSlice;
use PHPUnit\Framework\TestCase;

final class SsrfRuntimeSliceParityTest extends TestCase
{
    public function testSsrfParityContractsAreCoveredByStep6HookPlan(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new SsrfRuntimeSlice($backend);
        $slice->bootstrap();

        $hookSet = array_fill_keys(array_keys($backend->hooks()), true);
        $contractIds = array_map(
            static fn (array $contract): string => $contract['id'],
            array_values(array_filter(
                LegacyParityCatalog::contracts(),
                static fn (array $contract): bool => str_starts_with($contract['id'], 'sink.ssrf.')
            ))
        );

        foreach ($contractIds as $contractId) {
            self::assertArrayHasKey(
                $contractId,
                $hookSet,
                sprintf('SSRF contract hook missing from Step 6 plan: %s', $contractId)
            );
        }
    }

    public function testCurlExecContractIsActionableWhenUrlWasTrackedFromSetopt(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new SsrfRuntimeSlice($backend);
        $slice->bootstrap();

        $handle = new \stdClass();
        $backend->dispatchPreHook('aux.ssrf.curl_setopt', array(
            $handle,
            defined('CURLOPT_URL') ? constant('CURLOPT_URL') : 10002,
            TaintedValue::tainted('http://xtanzi.attacker.tld/path', 'query.url'),
        ));
        $backend->dispatchPreHook('sink.ssrf.curl_exec', array($handle));

        $detectors = array_map(
            static fn ($finding): string => $finding->detector(),
            $slice->findings()
        );
        self::assertSame(
            array('taint-input-detector', 'payload-keyword-detector'),
            $detectors
        );
    }

    public function testCurlMultiExecIsActionableWhenHandleWasAddedToMulti(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new SsrfRuntimeSlice($backend);
        $slice->bootstrap();

        $handle = new \stdClass();
        $multiHandle = new \stdClass();
        $backend->dispatchPreHook('aux.ssrf.curl_setopt', array(
            $handle,
            defined('CURLOPT_URL') ? constant('CURLOPT_URL') : 10002,
            TaintedValue::tainted('http://xtanzi.attacker.tld/path', 'query.url'),
        ));
        $backend->dispatchPreHook('aux.ssrf.curl_multi_add_handle', array(
            $multiHandle,
            $handle,
        ));
        $backend->dispatchPreHook('sink.ssrf.curl_multi_exec', array(
            $multiHandle,
            0,
        ));

        $detectors = array_map(
            static fn ($finding): string => $finding->detector(),
            $slice->findings()
        );
        self::assertSame(
            array('taint-input-detector', 'payload-keyword-detector'),
            $detectors
        );
    }
}
