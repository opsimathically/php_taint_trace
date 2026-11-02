<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit\Verification;

use PhpTaintTrace\Verification\Verifier\VerifierRuntimeConfig;
use PHPUnit\Framework\TestCase;

final class VerifierRuntimeConfigTest extends TestCase
{
    public function testFromEnvironmentParsesValues(): void
    {
        $config = VerifierRuntimeConfig::fromEnvironment(array(
            'PHP_TAINT_TRACE_VERIFIER_RUNTIME_DIR' => '/tmp/verifier',
            'PHP_TAINT_TRACE_VERIFIER_REPLAY_TARGET' => 'remote_lab',
            'PHP_TAINT_TRACE_VERIFIER_LOCAL_BASE_URL' => 'http://127.0.0.1:18080',
            'PHP_TAINT_TRACE_VERIFIER_CALLBACK_BASE_URL' => 'http://127.0.0.1:19081',
            'PHP_TAINT_TRACE_VERIFIER_REMOTE_HOST' => '192.168.1.10',
            'PHP_TAINT_TRACE_VERIFIER_BATCH_SIZE' => '77',
            'PHP_TAINT_TRACE_VERIFIER_MAX_ATTEMPTS' => '3',
            'PHP_TAINT_TRACE_VERIFIER_STABILITY_ROUNDS' => '1',
            'PHP_TAINT_TRACE_VERIFIER_CLAIM_TTL_SECONDS' => '123',
            'PHP_TAINT_TRACE_VERIFIER_XSS_BROWSER_ENABLED' => '1',
            'PHP_TAINT_TRACE_VERIFIER_XSS_BROWSER_ENFORCE' => 'true',
            'PHP_TAINT_TRACE_VERIFIER_XSS_BROWSER_TIMEOUT_MS' => '9100',
            'PHP_TAINT_TRACE_VERIFIER_XSS_BROWSER_DRIVER_CMD' => 'node driver.mjs --url {url} --nonce {nonce}',
            'PHP_TAINT_TRACE_VERIFIER_CONFIG_FILE' => '/tmp/verifier.json',
        ));

        self::assertSame('/tmp/verifier', $config->runtimeDir());
        self::assertSame('remote_lab', $config->replayTarget());
        self::assertSame('http://127.0.0.1:18080', $config->localBaseUrl());
        self::assertSame('http://127.0.0.1:19081', $config->callbackBaseUrl());
        self::assertSame('192.168.1.10', $config->remoteHost());
        self::assertSame(77, $config->batchSize());
        self::assertSame(3, $config->maxAttempts());
        self::assertSame(1, $config->verificationRounds());
        self::assertSame(123, $config->claimTtlSeconds());
        self::assertTrue($config->xssBrowserEnabled());
        self::assertTrue($config->xssBrowserEnforce());
        self::assertSame(9100, $config->xssBrowserTimeoutMs());
        self::assertSame('node driver.mjs --url {url} --nonce {nonce}', $config->xssBrowserDriverCommand());
        self::assertNotNull($config->xssBrowserProbeRunner());
        self::assertSame('/tmp/verifier.json', $config->configFilePath());
    }

    public function testFromEnvironmentLoadsConfigFileAndAllowsEnvOverride(): void
    {
        $configFilePath = sys_get_temp_dir() . '/php-taint-trace-verifier-config-' . uniqid('', true) . '.json';
        $json = json_encode(array(
            'verifier' => array(
                'runtime_dir' => '/tmp/file-verifier',
                'replay_target' => 'remote_lab',
                'remote_host' => '10.20.30.40',
                'batch_size' => 120,
                'max_attempts' => 4,
                'stability_rounds' => 1,
                'claim_ttl_seconds' => 240,
                'xss_browser_enabled' => true,
                'xss_browser_enforce' => false,
                'xss_browser_timeout_ms' => 6500,
                'xss_browser_driver_cmd' => 'node xss_driver.mjs --url {url}',
            ),
        ), JSON_UNESCAPED_SLASHES);
        self::assertIsString($json);
        file_put_contents($configFilePath, $json);

        $config = VerifierRuntimeConfig::fromEnvironment(array(
            'PHP_TAINT_TRACE_VERIFIER_CONFIG_FILE' => $configFilePath,
            'PHP_TAINT_TRACE_VERIFIER_BATCH_SIZE' => '42',
        ));

        self::assertSame('/tmp/file-verifier', $config->runtimeDir());
        self::assertSame('remote_lab', $config->replayTarget());
        self::assertSame('10.20.30.40', $config->remoteHost());
        self::assertSame(42, $config->batchSize());
        self::assertSame(4, $config->maxAttempts());
        self::assertSame(1, $config->verificationRounds());
        self::assertSame(240, $config->claimTtlSeconds());
        self::assertTrue($config->xssBrowserEnabled());
        self::assertFalse($config->xssBrowserEnforce());
        self::assertSame(6500, $config->xssBrowserTimeoutMs());
        self::assertSame('node xss_driver.mjs --url {url}', $config->xssBrowserDriverCommand());
        self::assertSame($configFilePath, $config->configFilePath());
    }
}
