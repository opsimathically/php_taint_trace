<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit;

use PhpTaintTrace\Instrumentation\HookKind;
use PhpTaintTrace\Instrumentation\HookPhase;
use PhpTaintTrace\Instrumentation\LegacyBaselineHookPlanFactory;
use PHPUnit\Framework\TestCase;

final class LegacyBaselineHookPlanFactoryTest extends TestCase
{
    public function testCreatesExpectedLegacyHookCounts(): void
    {
        $plan = LegacyBaselineHookPlanFactory::create();

        self::assertCount(126, $plan->hooks());
        self::assertCount(93, $plan->hooksByKind(HookKind::FUNCTION));
        self::assertCount(19, $plan->hooksByKind(HookKind::METHOD));
        self::assertCount(14, $plan->hooksByKind(HookKind::OPCODE));
    }

    public function testIncludesKnownCrossCategorySharedPathHook(): void
    {
        $hooksById = $this->hooksById();

        self::assertArrayHasKey('sink.file.file_get_contents', $hooksById);
        self::assertArrayHasKey('sink.ssrf.file_get_contents', $hooksById);
        self::assertSame('file_get_contents', $hooksById['sink.file.file_get_contents']->target());
        self::assertSame('file_get_contents', $hooksById['sink.ssrf.file_get_contents']->target());
        self::assertSame(
            true,
            $hooksById['sink.ssrf.file_get_contents']->metadata()['legacy_shared_path']
        );
    }

    public function testIncludesExpectedMethodAndOpcodeTargets(): void
    {
        $hooksById = $this->hooksById();

        self::assertArrayHasKey('method.sqli.sqlite3.querySingle', $hooksById);
        self::assertSame(
            'SQLite3::querySingle',
            $hooksById['method.sqli.sqlite3.querySingle']->target()
        );
        self::assertArrayHasKey('method.file.splfileobject.__construct', $hooksById);
        self::assertSame(
            'SplFileObject::__construct',
            $hooksById['method.file.splfileobject.__construct']->target()
        );
        self::assertArrayHasKey('sink.rce.mail', $hooksById);
        self::assertArrayHasKey('sink.ssrf.stream_socket_client', $hooksById);
        self::assertArrayHasKey('sink.ssrf.curl_multi_exec', $hooksById);
        self::assertArrayHasKey('method.ssrf.soapclient.__construct', $hooksById);
        self::assertArrayHasKey('method.ssrf.soapclient.__setLocation', $hooksById);
        self::assertArrayHasKey('sink.sqli.sqlsrv_query', $hooksById);
        self::assertArrayHasKey('sink.sqli.sqlsrv_prepare', $hooksById);
        self::assertArrayHasKey('sink.sqli.mysqli_execute_query', $hooksById);
        self::assertArrayHasKey('method.sqli.mysqli.execute_query', $hooksById);
        self::assertArrayHasKey('sink.file.symlink', $hooksById);
        self::assertArrayHasKey('sink.xxe.simplexml_load_string', $hooksById);
        self::assertArrayHasKey('method.xxe.domdocument.load', $hooksById);
        self::assertArrayHasKey('method.xxe.domdocument.loadXML', $hooksById);
        self::assertArrayHasKey('method.xxe.xmlreader.open', $hooksById);
        self::assertArrayHasKey('method.xxe.xmlreader.XML', $hooksById);
        self::assertSame(
            HookPhase::REPLACE,
            $hooksById['method.sqli.sqlite3.querySingle']->phase()
        );

        self::assertArrayHasKey('opcode.include_or_eval', $hooksById);
        self::assertSame(
            'XMARK_INCLUDE_OR_EVAL',
            $hooksById['opcode.include_or_eval']->target()
        );
        self::assertSame(
            HookPhase::BEFORE,
            $hooksById['opcode.include_or_eval']->phase()
        );
    }

    /**
     * @return array<string, \PhpTaintTrace\Instrumentation\HookDefinition>
     */
    private function hooksById(): array
    {
        $result = array();
        foreach (LegacyBaselineHookPlanFactory::create()->hooks() as $hook) {
            $result[$hook->id()] = $hook;
        }

        return $result;
    }
}
