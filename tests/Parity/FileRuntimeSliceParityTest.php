<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Parity;

use PhpTaintTrace\Instrumentation\Backend\ArrayInstrumentationBackend;
use PhpTaintTrace\Runtime\FileRuntimeSlice;
use PHPUnit\Framework\TestCase;

final class FileRuntimeSliceParityTest extends TestCase
{
    public function testFileParityContractsAreCoveredByStep7HookPlan(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new FileRuntimeSlice($backend);
        $slice->bootstrap();

        $hookSet = array_fill_keys(array_keys($backend->hooks()), true);
        $contractIds = array_map(
            static fn (array $contract): string => $contract['id'],
            array_values(array_filter(
                LegacyParityCatalog::contracts(),
                static fn (array $contract): bool => str_starts_with($contract['id'], 'sink.file.')
            ))
        );

        foreach ($contractIds as $contractId) {
            self::assertArrayHasKey(
                $contractId,
                $hookSet,
                sprintf('File contract hook missing from Step 7 plan: %s', $contractId)
            );
        }
    }
}
