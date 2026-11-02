<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit;

use PhpTaintTrace\Instrumentation\Backend\ArrayInstrumentationBackend;
use PhpTaintTrace\Instrumentation\BaselineHookPlan;
use PhpTaintTrace\Instrumentation\HookDefinition;
use PhpTaintTrace\Instrumentation\HookHandlerRegistry;
use PhpTaintTrace\Instrumentation\InstrumentationCapabilities;
use PhpTaintTrace\Instrumentation\RuntimeInstrumentationBootstrap;
use PHPUnit\Framework\TestCase;

final class RuntimeInstrumentationBootstrapTest extends TestCase
{
    public function testBootstrapSkipsUnsupportedHookKinds(): void
    {
        $backend = new ArrayInstrumentationBackend(new InstrumentationCapabilities(
            functionHooks: true,
            methodHooks: true,
            opcodeHooks: false,
            taintTracking: true,
            symbolRenaming: false
        ));
        $bootstrap = new RuntimeInstrumentationBootstrap($backend);

        $plan = new BaselineHookPlan(
            HookDefinition::function('f.one', 'trim'),
            HookDefinition::method('m.one', 'PDO', 'query'),
            HookDefinition::opcode('o.one', 'XMARK_ECHO')
        );

        $handlers = new HookHandlerRegistry();
        $handlers->register('f.one', static function (): void {
        });
        $handlers->register('m.one', static function (): void {
        });

        $report = $bootstrap->bootstrap($plan, $handlers);

        self::assertSame('array-backend', $report->backendName());
        self::assertSame(2, $report->registeredCount());
        self::assertSame(1, $report->skippedCount());
        self::assertArrayHasKey('o.one', $report->skippedHookReasons());
    }

    public function testBootstrapReportsMissingHandlersInStrictMode(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $bootstrap = new RuntimeInstrumentationBootstrap($backend);

        $plan = new BaselineHookPlan(
            HookDefinition::function('f.one', 'trim'),
            HookDefinition::opcode('o.one', 'XMARK_ECHO')
        );

        $handlers = new HookHandlerRegistry(true);
        $report = $bootstrap->bootstrap($plan, $handlers);

        self::assertSame(0, $report->registeredCount());
        self::assertSame(2, $report->skippedCount());
        self::assertStringContainsString(
            'Missing hook handler',
            $report->skippedHookReasons()['f.one']
        );
    }
}
