<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Verifier;

use PhpTaintTrace\Verification\Oracle\BrowserProbeRunnerInterface;
use PhpTaintTrace\Verification\Oracle\CommandBrowserProbeRunner;

final class VerifierRuntimeConfig
{
    private const DEFAULT_CONFIG_FILE_PATH = '/etc/php_taint_trace/verifier.json';

    /**
     * @param array<string, mixed>|null $env
     */
    public static function fromEnvironment(?array $env = null): self
    {
        $configFilePath = self::envStringFromEnvOnly(
            'PHP_TAINT_TRACE_VERIFIER_CONFIG_FILE',
            self::DEFAULT_CONFIG_FILE_PATH,
            $env
        );
        $config = self::loadConfigFile($configFilePath);

        return new self(
            runtimeDir: self::resolveString(
                'PHP_TAINT_TRACE_VERIFIER_RUNTIME_DIR',
                'runtime_dir',
                '.php_taint_trace_runtime/verifier',
                $env,
                $config
            ),
            replayTarget: self::resolveString(
                'PHP_TAINT_TRACE_VERIFIER_REPLAY_TARGET',
                'replay_target',
                'local',
                $env,
                $config
            ),
            localBaseUrl: self::resolveString(
                'PHP_TAINT_TRACE_VERIFIER_LOCAL_BASE_URL',
                'local_base_url',
                'http://127.0.0.1:8080',
                $env,
                $config
            ),
            callbackBaseUrl: self::resolveString(
                'PHP_TAINT_TRACE_VERIFIER_CALLBACK_BASE_URL',
                'callback_base_url',
                '',
                $env,
                $config
            ),
            remoteHost: self::resolveString(
                'PHP_TAINT_TRACE_VERIFIER_REMOTE_HOST',
                'remote_host',
                '127.0.0.1',
                $env,
                $config
            ),
            batchSize: self::resolveInt(
                'PHP_TAINT_TRACE_VERIFIER_BATCH_SIZE',
                'batch_size',
                200,
                $env,
                $config
            ),
            maxAttempts: self::resolveInt(
                'PHP_TAINT_TRACE_VERIFIER_MAX_ATTEMPTS',
                'max_attempts',
                2,
                $env,
                $config
            ),
            verificationRounds: self::resolveInt(
                'PHP_TAINT_TRACE_VERIFIER_STABILITY_ROUNDS',
                'stability_rounds',
                2,
                $env,
                $config
            ),
            claimTtlSeconds: self::resolveInt(
                'PHP_TAINT_TRACE_VERIFIER_CLAIM_TTL_SECONDS',
                'claim_ttl_seconds',
                300,
                $env,
                $config
            ),
            xssBrowserEnabled: self::resolveBool(
                'PHP_TAINT_TRACE_VERIFIER_XSS_BROWSER_ENABLED',
                'xss_browser_enabled',
                false,
                $env,
                $config
            ),
            xssBrowserEnforce: self::resolveBool(
                'PHP_TAINT_TRACE_VERIFIER_XSS_BROWSER_ENFORCE',
                'xss_browser_enforce',
                false,
                $env,
                $config
            ),
            xssBrowserTimeoutMs: self::resolveInt(
                'PHP_TAINT_TRACE_VERIFIER_XSS_BROWSER_TIMEOUT_MS',
                'xss_browser_timeout_ms',
                8000,
                $env,
                $config
            ),
            xssBrowserDriverCommand: self::resolveString(
                'PHP_TAINT_TRACE_VERIFIER_XSS_BROWSER_DRIVER_CMD',
                'xss_browser_driver_cmd',
                '',
                $env,
                $config
            ),
            configFilePath: $configFilePath
        );
    }

    public function __construct(
        private readonly string $runtimeDir,
        private readonly string $replayTarget,
        private readonly string $localBaseUrl,
        private readonly string $callbackBaseUrl,
        private readonly string $remoteHost,
        private readonly int $batchSize,
        private readonly int $maxAttempts,
        private readonly int $verificationRounds,
        private readonly int $claimTtlSeconds,
        private readonly bool $xssBrowserEnabled,
        private readonly bool $xssBrowserEnforce,
        private readonly int $xssBrowserTimeoutMs,
        private readonly string $xssBrowserDriverCommand,
        private readonly string $configFilePath = self::DEFAULT_CONFIG_FILE_PATH
    ) {
    }

    public function runtimeDir(): string
    {
        return $this->runtimeDir;
    }

    public function replayTarget(): string
    {
        return $this->replayTarget;
    }

    public function localBaseUrl(): string
    {
        return $this->localBaseUrl;
    }

    public function remoteHost(): string
    {
        return $this->remoteHost;
    }

    public function callbackBaseUrl(): string
    {
        return $this->callbackBaseUrl;
    }

    public function batchSize(): int
    {
        return $this->batchSize;
    }

    public function maxAttempts(): int
    {
        return $this->maxAttempts;
    }

    public function verificationRounds(): int
    {
        return $this->verificationRounds;
    }

    public function claimTtlSeconds(): int
    {
        return $this->claimTtlSeconds;
    }

    public function configFilePath(): string
    {
        return $this->configFilePath;
    }

    public function xssBrowserEnabled(): bool
    {
        return $this->xssBrowserEnabled;
    }

    public function xssBrowserEnforce(): bool
    {
        return $this->xssBrowserEnforce;
    }

    public function xssBrowserTimeoutMs(): int
    {
        return $this->xssBrowserTimeoutMs;
    }

    public function xssBrowserDriverCommand(): string
    {
        return $this->xssBrowserDriverCommand;
    }

    public function xssBrowserProbeRunner(): ?BrowserProbeRunnerInterface
    {
        if (!$this->xssBrowserEnabled) {
            return null;
        }

        if (trim($this->xssBrowserDriverCommand) === '') {
            return null;
        }

        return new CommandBrowserProbeRunner($this->xssBrowserDriverCommand);
    }

    public function replayRunner(): ReplayRunnerInterface
    {
        if ($this->replayTarget === 'remote_lab') {
            return new RemoteLabReplayRunner($this->remoteHost);
        }

        return new LocalReplayRunner(
            $this->localBaseUrl,
            callbackBaseOverride: $this->callbackBaseUrl
        );
    }

    /**
     * @param array<string, mixed>|null $env
     */
    private static function envStringFromEnvOnly(string $name, string $default, ?array $env): string
    {
        if ($env !== null && array_key_exists($name, $env) && $env[$name] !== null) {
            $resolved = trim((string) $env[$name]);
            return $resolved === '' ? $default : $resolved;
        }

        $value = getenv($name);
        if ($value === false) {
            return $default;
        }

        $resolved = trim((string) $value);
        return $resolved === '' ? $default : $resolved;
    }

    /**
     * @param array<string, mixed>|null $env
     * @param array<string, mixed> $config
     */
    private static function resolveString(
        string $envName,
        string $configKey,
        string $default,
        ?array $env,
        array $config
    ): string {
        $sentinel = "\0";
        $envValue = self::envStringFromEnvOnly($envName, $sentinel, $env);
        if ($envValue !== $sentinel) {
            return $envValue;
        }

        if (array_key_exists($configKey, $config) && is_scalar($config[$configKey])) {
            $resolved = trim((string) $config[$configKey]);
            return $resolved === '' ? $default : $resolved;
        }

        if (array_key_exists($envName, $config) && is_scalar($config[$envName])) {
            $resolved = trim((string) $config[$envName]);
            return $resolved === '' ? $default : $resolved;
        }

        return $default;
    }

    /**
     * @param array<string, mixed>|null $env
     * @param array<string, mixed> $config
     */
    private static function resolveInt(
        string $envName,
        string $configKey,
        int $default,
        ?array $env,
        array $config
    ): int {
        $value = self::resolveString($envName, $configKey, (string) $default, $env, $config);
        if (!preg_match('/^-?\d+$/', $value)) {
            return $default;
        }

        $resolved = (int) $value;
        return $resolved > 0 ? $resolved : $default;
    }

    /**
     * @param array<string, mixed>|null $env
     * @param array<string, mixed> $config
     */
    private static function resolveBool(
        string $envName,
        string $configKey,
        bool $default,
        ?array $env,
        array $config
    ): bool {
        $sentinel = "\0";
        $envValue = self::envStringFromEnvOnly($envName, $sentinel, $env);
        if ($envValue !== $sentinel) {
            return self::boolFromString($envValue, $default);
        }

        $raw = null;
        if (array_key_exists($configKey, $config)) {
            $raw = $config[$configKey];
        } elseif (array_key_exists($envName, $config)) {
            $raw = $config[$envName];
        }

        if ($raw === null) {
            return $default;
        }

        if (is_bool($raw)) {
            return $raw;
        }

        if (is_scalar($raw)) {
            return self::boolFromString((string) $raw, $default);
        }

        return $default;
    }

    private static function boolFromString(string $value, bool $default): bool
    {
        $normalized = strtolower(trim($value));
        if ($normalized === '') {
            return $default;
        }

        if (in_array($normalized, array('1', 'true', 'yes', 'on'), true)) {
            return true;
        }

        if (in_array($normalized, array('0', 'false', 'no', 'off'), true)) {
            return false;
        }

        return $default;
    }

    /**
     * @return array<string, mixed>
     */
    private static function loadConfigFile(string $path): array
    {
        if (!is_file($path)) {
            return array();
        }

        $raw = @file_get_contents($path);
        if (!is_string($raw)) {
            return array();
        }

        $decoded = json_decode($raw, true);
        if (!is_array($decoded)) {
            error_log('[php_taint_trace] unable to parse verifier config file: ' . $path);
            return array();
        }

        if (isset($decoded['verifier']) && is_array($decoded['verifier'])) {
            return $decoded['verifier'];
        }

        return $decoded;
    }
}
