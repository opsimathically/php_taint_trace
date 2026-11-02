<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit\Verification;

use PHPUnit\Framework\TestCase;

abstract class ScriptTestCase extends TestCase
{
    protected string $tmpRoot = '';

    protected function setUp(): void
    {
        parent::setUp();
        $this->tmpRoot = sys_get_temp_dir() . '/' . $this->tempRootPrefix() . '-' . uniqid('', true);
        mkdir($this->tmpRoot, 0775, true);
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        if ($this->tmpRoot !== '' && is_dir($this->tmpRoot)) {
            $this->deleteDir($this->tmpRoot);
        }
    }

    protected function tempRootPrefix(): string
    {
        return 'php-taint-trace-script';
    }

    /**
     * @param string[] $command
     * @param array<string, string> $env
     * @return array{exit_code: int, stdout: string, stderr: string}
     */
    protected function runScript(array $command, array $env = array()): array
    {
        $descriptors = array(
            0 => array('file', '/dev/null', 'r'),
            1 => array('pipe', 'w'),
            2 => array('pipe', 'w'),
        );

        $processEnv = null;
        if ($env !== array()) {
            $processEnv = array_merge($_ENV, $env);
        }

        $process = proc_open(
            $command,
            $descriptors,
            $pipes,
            dirname(__DIR__, 3),
            $processEnv
        );
        self::assertTrue(is_resource($process));

        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);

        $exitCode = proc_close($process);

        return array(
            'exit_code' => $exitCode,
            'stdout' => is_string($stdout) ? $stdout : '',
            'stderr' => is_string($stderr) ? $stderr : '',
        );
    }

    protected function allocateEphemeralPort(): int
    {
        $server = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
        self::assertNotFalse($server, sprintf('failed to allocate ephemeral port: %s', $errstr));
        $name = stream_socket_get_name($server, false);
        fclose($server);
        self::assertIsString($name);
        $segments = explode(':', $name);
        return (int) end($segments);
    }

    protected function deleteDir(string $path): void
    {
        $items = scandir($path);
        if (!is_array($items)) {
            return;
        }

        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }

            $child = $path . '/' . $item;
            if (is_dir($child)) {
                $this->deleteDir($child);
                continue;
            }

            @unlink($child);
        }

        @rmdir($path);
    }
}
