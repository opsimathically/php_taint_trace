<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Parity;

use PhpTaintTrace\Instrumentation\Backend\ArrayInstrumentationBackend;
use PhpTaintTrace\Runtime\XssRuntimeSlice;
use PHPUnit\Framework\TestCase;

final class XssRuntimeSliceParityTest extends TestCase
{
    public function testXssParityContractsAreCoveredByStep8HookPlan(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new XssRuntimeSlice($backend);
        $slice->bootstrap();

        $hookSet = array_fill_keys(array_keys($backend->hooks()), true);
        $contractIds = array_map(
            static fn (array $contract): string => $contract['id'],
            array_values(array_filter(
                LegacyParityCatalog::contracts(),
                static fn (array $contract): bool => str_starts_with($contract['id'], 'sink.xss.')
            ))
        );

        foreach ($contractIds as $contractId) {
            self::assertArrayHasKey(
                $contractId,
                $hookSet,
                sprintf('XSS contract hook missing from Step 8 plan: %s', $contractId)
            );
        }
    }
}
