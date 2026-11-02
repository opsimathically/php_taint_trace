<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Parity;

use PhpTaintTrace\Instrumentation\Backend\ArrayInstrumentationBackend;
use PhpTaintTrace\Runtime\BaselineRuntime;
use PHPUnit\Framework\TestCase;

final class BaselineRuntimeParityCoverageTest extends TestCase
{
    public function testAllLegacyContractsAreCoveredByBaselineRuntimeHookPlan(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $runtime = new BaselineRuntime($backend);
        $runtime->bootstrap();

        $hookSet = array_fill_keys(array_keys($backend->hooks()), true);
        foreach (LegacyParityCatalog::contracts() as $contract) {
            $contractId = $contract['id'];
            if (isset($hookSet[$contractId])) {
                continue;
            }

            $mappedHooks = $this->contractToMappedHooks((string) $contractId);
            self::assertNotEmpty(
                $mappedHooks,
                sprintf('Missing direct hook and no mapping found for contract: %s', $contractId)
            );

            foreach ($mappedHooks as $mappedHookId) {
                self::assertArrayHasKey(
                    $mappedHookId,
                    $hookSet,
                    sprintf('Contract %s is missing mapped hook %s', $contractId, $mappedHookId)
                );
            }
        }
    }

    /**
     * @return string[]
     */
    private function contractToMappedHooks(string $contractId): array
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
