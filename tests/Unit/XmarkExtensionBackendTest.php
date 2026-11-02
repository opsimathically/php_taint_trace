<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit;

use PhpTaintTrace\Instrumentation\HookDefinition;
use PhpTaintTrace\Instrumentation\HookKind;
use PhpTaintTrace\Instrumentation\HookPhase;
use PhpTaintTrace\Instrumentation\Backend\XmarkExtensionBackend;
use PhpTaintTrace\Instrumentation\HookContext;
use PhpTaintTrace\Instrumentation\InstrumentationCapabilities;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use RuntimeException;

final class XmarkExtensionBackendTest extends TestCase
{
    public function testCanUseInjectedMarkerAndChecker(): void
    {
        $markedValues = array();
        $backend = new XmarkExtensionBackend(
            registerHook: static function (): void {
            },
            marker: static function (mixed &$value, bool $recursive, ?string $source) use (&$markedValues): void {
                $markedValues[] = array(
                    'value' => $value,
                    'recursive' => $recursive,
                    'source' => $source,
                );
            },
            checker: static fn (mixed $value): bool => $value === 'tainted',
            capabilityOverride: InstrumentationCapabilities::full()
        );

        $value = 'example';
        $backend->markTainted($value, true, '_GET');

        self::assertCount(1, $markedValues);
        self::assertSame('_GET', $markedValues[0]['source']);
        self::assertTrue($backend->isTainted('tainted'));
        self::assertFalse($backend->isTainted('safe'));
    }

    public function testBridgeMapsNativeContextToHookContextPreAndPostShapes(): void
    {
        $backend = new XmarkExtensionBackend(
            capabilityOverride: InstrumentationCapabilities::full()
        );

        $rceHook = HookDefinition::function(
            id: 'sink.rce.system',
            functionName: 'system',
            phase: HookPhase::REPLACE,
            metadata: array('domain' => 'rce')
        );
        $filterHook = HookDefinition::function(
            id: 'filter.strtolower',
            functionName: 'strtolower',
            phase: HookPhase::REPLACE,
            metadata: array('domain' => 'filter')
        );

        $bridgeFactory = new ReflectionMethod(XmarkExtensionBackend::class, 'nativeContextBridge');
        $bridgeFactory->setAccessible(true);

        $preBridge = $bridgeFactory->invoke(
            $backend,
            $rceHook,
            static function (HookContext $context): string {
                return $context->hasResult() ? 'post' : 'pre';
            }
        );
        $postBridge = $bridgeFactory->invoke(
            $backend,
            $filterHook,
            static function (HookContext $context): string {
                return $context->hasResult() ? 'post' : 'pre';
            }
        );

        $preResult = $preBridge(array(
            'arguments' => array('id'),
            'metadata' => array('k' => 'v'),
            'phase' => 'before',
            'has_result' => false,
        ));
        self::assertSame('pre', $preResult);

        $postResult = $postBridge(array(
            'arguments' => array('id'),
            'metadata' => array('k' => 'v'),
            'phase' => 'after',
            'has_result' => true,
            'result' => 'ok',
        ));
        self::assertSame('post', $postResult);
    }

    public function testCapabilitiesRequireNativeRegistrarWithoutOverrides(): void
    {
        $backend = new XmarkExtensionBackend();
        $capabilities = $backend->capabilities();

        $expectedRegistrar = function_exists('xmark_register_hook');
        $expectedOpcodeRegistrar = function_exists('xregister_opcode_callback');
        self::assertSame($expectedRegistrar, $capabilities->supports(HookKind::FUNCTION));
        self::assertSame($expectedRegistrar, $capabilities->supports(HookKind::METHOD));
        self::assertSame($expectedOpcodeRegistrar, $capabilities->supports(HookKind::OPCODE));
    }

    public function testRegisterHookThrowsWhenInjectedNativeFunctionRegistrarFails(): void
    {
        $backend = new XmarkExtensionBackend(
            nativeHookRegistrar: static function (): bool {
                return false;
            }
        );

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Native hook registration failed');

        $backend->registerHook(
            HookDefinition::function(
                id: 'sink.rce.system',
                functionName: 'system',
                phase: HookPhase::REPLACE,
                metadata: array('domain' => 'sink')
            ),
            static function (HookContext $_context): void {
            }
        );
    }

    public function testRegisterHookUsesInjectedNativeOpcodeRegistrar(): void
    {
        $captured = array();
        $backend = new XmarkExtensionBackend(
            nativeOpcodeRegistrar: static function (
                string|int $opcode,
                callable $bridge,
                string $phase,
                ?string $id
            ) use (&$captured): bool {
                $captured = array(
                    'opcode' => $opcode,
                    'phase' => $phase,
                    'id' => $id,
                    'bridge_type' => gettype($bridge),
                );
                return true;
            }
        );

        $backend->registerHook(
            HookDefinition::opcode(
                id: 'opcode.echo',
                opcode: 'XMARK_ECHO',
                phase: HookPhase::BEFORE,
                metadata: array('domain' => 'opcode')
            ),
            static function (HookContext $_context): void {
            }
        );

        self::assertSame('XMARK_ECHO', $captured['opcode'] ?? null);
        self::assertSame('before', $captured['phase'] ?? null);
        self::assertSame('opcode.echo', $captured['id'] ?? null);
        self::assertSame('object', $captured['bridge_type'] ?? null);
    }
}
