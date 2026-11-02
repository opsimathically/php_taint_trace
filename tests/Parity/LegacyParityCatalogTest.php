<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Parity;

use PHPUnit\Framework\TestCase;

final class LegacyParityCatalogTest extends TestCase
{
    public function testInventoryCountsMatchLegacyBaseline(): void
    {
        $counts = LegacyParityCatalog::inventoryCounts();

        self::assertSame(28, $counts['filters']);
        self::assertSame(14, $counts['opcode_hooks']);
        self::assertSame(17, $counts['sink_file']);
        self::assertSame(7, $counts['sink_rce']);
        self::assertSame(14, $counts['sink_sqli']);
        self::assertSame(4, $counts['sink_ssrf']);
        self::assertSame(3, $counts['sink_xss']);
        self::assertSame(45, $counts['sink_total']);
    }

    public function testCatalogLegacyFilesMatchPrvdOldTree(): void
    {
        self::assertSame(
            LegacyParityCatalog::legacyTestFiles(),
            LegacyParityCatalog::discoverLegacyTestFilesFromPrvdOld()
        );
    }

    public function testContractsCoverEachLegacyTestExactlyOnce(): void
    {
        $contracts = LegacyParityCatalog::contracts();
        $legacyFiles = LegacyParityCatalog::legacyTestFiles();

        self::assertCount(count($legacyFiles), $contracts);

        $contractIds = array();
        $contractLegacyFiles = array();
        foreach ($contracts as $contract) {
            self::assertIsString($contract['id']);
            self::assertIsString($contract['legacy_test_file']);
            self::assertIsString($contract['mode']);
            self::assertIsArray($contract['expectation']);

            $contractIds[] = $contract['id'];
            $contractLegacyFiles[] = $contract['legacy_test_file'];
        }

        self::assertCount(count($contractIds), array_unique($contractIds));
        self::assertCount(count($contractLegacyFiles), array_unique($contractLegacyFiles));

        sort($contractLegacyFiles);
        self::assertSame($legacyFiles, $contractLegacyFiles);
    }

    public function testKnownGapsAreExplicitlyDocumentedInContracts(): void
    {
        $contractsById = $this->contractsById();
        $knownGaps = LegacyParityCatalog::knownGaps();
        foreach ($knownGaps as $contractId => $reason) {
            self::assertArrayHasKey($contractId, $contractsById);
            self::assertNotEmpty($contractsById[$contractId]['notes']);
            self::assertIsString($reason);
            self::assertNotSame('', trim($reason));
        }

        self::assertIsArray($knownGaps);
    }

    public function testRepresentativeLegacyQuirksAreLocked(): void
    {
        $contractsById = $this->contractsById();

        self::assertSame(
            'taint_propagation_mixed',
            $contractsById['filter.json_decode']['mode']
        );
        self::assertSame(
            false,
            $contractsById['filter.json_decode']['expectation']['object_decode_taint_result']
        );
        self::assertSame(
            true,
            $contractsById['filter.json_decode']['expectation']['assoc_decode_taint_result']
        );

        self::assertSame(
            'taint_and_payload',
            $contractsById['sink.ssrf.curl_exec']['mode']
        );
        self::assertSame(
            true,
            $contractsById['sink.ssrf.curl_exec']['expectation']['taint_event_when_taint_mode_enabled']
        );
        self::assertSame(
            true,
            $contractsById['sink.ssrf.curl_exec']['expectation']['payload_event']
        );

        self::assertSame(
            'behavior_only',
            $contractsById['sink.sqli.mysqli_init']['mode']
        );
        self::assertSame(
            'mysqli',
            $contractsById['sink.sqli.mysqli_init']['expectation']['returns_instance_of']
        );

        self::assertSame(
            'taint_and_payload',
            $contractsById['sink.rce.unserialize']['mode']
        );
        self::assertSame(
            true,
            $contractsById['sink.rce.unserialize']['expectation']['payload_event']
        );

        self::assertSame(
            'taint_and_payload',
            $contractsById['opcode.do_icall']['mode']
        );
        self::assertSame(
            true,
            $contractsById['opcode.do_icall']['expectation']['payload_event']
        );
        self::assertSame(
            'taint_only',
            $contractsById['opcode.exit']['mode']
        );
        self::assertSame(
            true,
            $contractsById['opcode.exit']['expectation']['taint_event_when_taint_mode_enabled']
        );
    }

    /**
     * @return array<string, array<string, mixed>>
     */
    private function contractsById(): array
    {
        $result = array();
        foreach (LegacyParityCatalog::contracts() as $contract) {
            $result[$contract['id']] = $contract;
        }

        return $result;
    }
}
