<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Parity;

use PhpTaintTrace\Instrumentation\Backend\ArrayInstrumentationBackend;
use PhpTaintTrace\Runtime\FilterRuntimeSlice;
use PHPUnit\Framework\TestCase;

final class FilterRuntimeSliceParityTest extends TestCase
{
    public function testFilterParityContractsAreCoveredByStep10HookPlan(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new FilterRuntimeSlice($backend);
        $slice->bootstrap();

        $hookSet = array_fill_keys(array_keys($backend->hooks()), true);
        $contractIds = array_map(
            static fn (array $contract): string => $contract['id'],
            array_values(array_filter(
                LegacyParityCatalog::contracts(),
                static fn (array $contract): bool => str_starts_with($contract['id'], 'filter.')
            ))
        );

        foreach ($contractIds as $contractId) {
            self::assertArrayHasKey(
                $contractId,
                $hookSet,
                sprintf('Filter contract hook missing from Step 10 plan: %s', $contractId)
            );
        }
    }
}
