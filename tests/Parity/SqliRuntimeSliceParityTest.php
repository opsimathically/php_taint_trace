<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Parity;

use PhpTaintTrace\Instrumentation\Backend\ArrayInstrumentationBackend;
use PhpTaintTrace\Runtime\SqliRuntimeSlice;
use PHPUnit\Framework\TestCase;

final class SqliRuntimeSliceParityTest extends TestCase
{
    public function testSqliParityContractsAreCoveredByStep5HookPlan(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $slice = new SqliRuntimeSlice($backend);
        $slice->bootstrap();

        $hookIds = array_keys($backend->hooks());
        $hookSet = array_fill_keys($hookIds, true);

        $contractIds = array_map(
            static fn (array $contract): string => $contract['id'],
            array_values(array_filter(
                LegacyParityCatalog::contracts(),
                static fn (array $contract): bool => str_starts_with($contract['id'], 'sink.sqli.')
            ))
        );

        foreach ($contractIds as $contractId) {
            if (isset($hookSet[$contractId])) {
                continue;
            }

            $mappedHooks = $this->contractToMethodHookCoverage($contractId);
            self::assertNotEmpty(
                $mappedHooks,
                sprintf('Missing direct SQLi hook coverage and no method mapping found for contract: %s', $contractId)
            );

            foreach ($mappedHooks as $mappedHookId) {
                self::assertArrayHasKey(
                    $mappedHookId,
                    $hookSet,
                    sprintf('SQLi contract %s is missing mapped hook %s', $contractId, $mappedHookId)
                );
            }
        }
    }

    /**
     * @return string[]
     */
    private function contractToMethodHookCoverage(string $contractId): array
    {
        return match ($contractId) {
            'sink.sqli.mysqli' => array(
                'method.sqli.mysqli.query',
                'method.sqli.mysqli.prepare',
                'method.sqli.mysqli.real_query',
                'method.sqli.mysqli.multi_query',
            ),
            'sink.sqli.pdo' => array(
                'method.sqli.pdo.query',
                'method.sqli.pdo.prepare',
                'method.sqli.pdo.exec',
            ),
            'sink.sqli.sqlite3' => array(
                'method.sqli.sqlite3.exec',
                'method.sqli.sqlite3.query',
                'method.sqli.sqlite3.prepare',
                'method.sqli.sqlite3.querySingle',
            ),
            default => array(),
        };
    }
}
