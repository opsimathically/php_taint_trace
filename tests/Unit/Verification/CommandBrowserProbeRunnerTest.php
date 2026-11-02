<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit\Verification;

use PhpTaintTrace\Verification\Oracle\BrowserProbeRequest;
use PhpTaintTrace\Verification\Oracle\CommandBrowserProbeRunner;
use PhpTaintTrace\Verification\Verifier\ReplayRequest;
use PHPUnit\Framework\TestCase;

final class CommandBrowserProbeRunnerTest extends TestCase
{
    public function testProbeParsesSuccessfulDriverOutput(): void
    {
        $driverPath = $this->writeDriverScript(<<<'PHP'
<?php
declare(strict_types=1);

$args = $argv;
array_shift($args);
$parsed = array();
for ($i = 0; $i < count($args); $i++) {
    $key = $args[$i] ?? '';
    if (!is_string($key) || !str_starts_with($key, '--')) {
        continue;
    }
    $name = substr($key, 2);
    $value = $args[$i + 1] ?? '1';
    if (is_string($value) && !str_starts_with($value, '--')) {
        $parsed[$name] = $value;
        $i++;
        continue;
    }
    $parsed[$name] = '1';
}

echo json_encode(array(
    'success' => true,
    'executed' => true,
    'observed_nonce' => (string) ($parsed['nonce'] ?? ''),
    'target_url' => (string) ($parsed['url'] ?? ''),
), JSON_UNESCAPED_SLASHES);
PHP
);

        $runner = new CommandBrowserProbeRunner(
            'php ' . escapeshellarg($driverPath) . ' --url {url} --nonce {nonce} --timeout-ms {timeout_ms}'
        );
        $result = $runner->probe($this->probeRequest('http://127.0.0.1:19081/?name=test', 'nonce-1'));

        self::assertTrue($result->success());
        self::assertTrue($result->executionObserved());
        self::assertNull($result->error());
        self::assertSame(0, $result->exitCode());
        self::assertStringContainsString('nonce-1', $result->stdout());
    }

    public function testProbeReturnsFailureWhenDriverOutputIsInvalidJson(): void
    {
        $driverPath = $this->writeDriverScript(<<<'PHP'
<?php
declare(strict_types=1);

fwrite(STDOUT, "not-json\n");
exit(2);
PHP
);

        $runner = new CommandBrowserProbeRunner('php ' . escapeshellarg($driverPath) . ' --url {url} --nonce {nonce}');
        $result = $runner->probe($this->probeRequest('http://127.0.0.1:19081/?name=test', 'nonce-2'));

        self::assertFalse($result->success());
        self::assertFalse($result->executionObserved());
        self::assertSame('browser probe output was not valid JSON', $result->error());
        self::assertSame(2, $result->exitCode());
    }

    private function probeRequest(string $url, string $nonce): BrowserProbeRequest
    {
        return new BrowserProbeRequest(
            $url,
            $nonce,
            8000,
            ReplayRequest::fromRequestUri('xss', 'GET', '/xss?name=guest')
        );
    }

    private function writeDriverScript(string $content): string
    {
        $path = sys_get_temp_dir() . '/php-taint-trace-browser-driver-' . uniqid('', true) . '.php';
        file_put_contents($path, $content);
        return $path;
    }
}

