<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit;

use PHPUnit\Framework\TestCase;

final class XmarkNativeSmokeTest extends TestCase
{
    public function testLegacyOpcodeConstantsAreExported(): void
    {
        $result = $this->runNativeScript(
            <<<'PHP'
echo (int) defined('XMARK_ECHO'), ',', (int) defined('XMARK_ASSIGN_CONCAT');
PHP
        );

        self::assertSame(0, $result['status']);
        self::assertSame('1,1', trim($result['output']));
    }

    public function testTaintIsKeyedByStringIdentityNotOnlyByValue(): void
    {
        $result = $this->runNativeScript(
            <<<'PHP'
$a = str_repeat('a', 3);
$b = implode('', array('a', 'a', 'a'));
$c = $a;
xmark($a);
echo (int) xcheck($a), (int) xcheck($b), (int) xcheck($c);
PHP
        );

        self::assertSame(0, $result['status']);
        self::assertSame('101', trim($result['output']));
    }

    public function testOpcodeCallbackDispatchesOnIncludedScript(): void
    {
        $result = $this->runNativeScript(
            <<<'PHP'
$hits = 0;
xregister_opcode_callback(XMARK_ECHO, function (array $context) use (&$hits): void {
    $hits++;
});
$file = sys_get_temp_dir() . '/xmark-opcode-' . uniqid('', true) . '.php';
file_put_contents($file, '<?php echo "hello";');
ob_start();
include $file;
ob_end_clean();
@unlink($file);
echo $hits;
PHP
        );

        self::assertSame(0, $result['status']);
        self::assertSame('1', trim($result['output']));
    }

    /**
     * @return array{status:int,output:string}
     */
    private function runNativeScript(string $code): array
    {
        $extensionPath = dirname(__DIR__, 2) . '/ext/xmark/modules/xmark.so';
        if (!is_file($extensionPath)) {
            self::markTestSkipped('Native xmark extension is not built at ext/xmark/modules/xmark.so');
        }

        $scriptPath = tempnam(sys_get_temp_dir(), 'xmark-native-');
        if ($scriptPath === false) {
            self::fail('Failed creating temp script for native extension smoke test.');
        }

        file_put_contents($scriptPath, "<?php\n" . $code . "\n");

        $cmd = sprintf(
            '%s -n -d extension=%s %s 2>&1',
            escapeshellcmd(PHP_BINARY),
            escapeshellarg($extensionPath),
            escapeshellarg($scriptPath)
        );

        $outputLines = array();
        $status = 0;
        exec($cmd, $outputLines, $status);
        @unlink($scriptPath);

        return array(
            'status' => $status,
            'output' => implode("\n", $outputLines),
        );
    }
}
