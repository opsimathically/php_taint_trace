<?php

declare(strict_types=1);

namespace PhpTaintTrace\Runtime;

final class AppRuntimeConfig
{
    private const OPCODE_HOOK_PROFILE_SAFE = 'safe';
    private const OPCODE_HOOK_PROFILE_FULL = 'full';
    private const VERIFIER_REPLAY_TARGET_LOCAL = 'local';
    private const VERIFIER_REPLAY_TARGET_REMOTE_LAB = 'remote_lab';
    private const REPORTING_BACKEND_JSONL = 'jsonl';
    private const REPORTING_BACKEND_SQLITE = 'sqlite';
    private const REPORTING_BACKEND_PDO = 'pdo';
    private const DEFAULT_CONFIG_FILE_PATH = '/etc/php_taint_trace/runtime.json';
    private const DEFAULT_REPORTING_TABLE = 'php_taint_trace_request_reports';

    public function __construct(
        private readonly bool $enabled = true,
        private readonly ?string $findingsFilePath = null,
        private readonly bool $emitErrorLog = true,
        private readonly bool $clearFindingsAfterFlush = true,
        private readonly bool $emitCandidates = false,
        private readonly bool $enableOpcodeHooks = false,
        private readonly string $opcodeHookProfile = self::OPCODE_HOOK_PROFILE_SAFE,
        private readonly bool $enableVerifier = false,
        private readonly string $verifierRuntimeDir = '.php_taint_trace_runtime/verifier',
        private readonly string $verifierReplayTarget = self::VERIFIER_REPLAY_TARGET_LOCAL,
        private readonly string $reportingBackend = self::REPORTING_BACKEND_JSONL,
        private readonly ?string $reportingDsn = null,
        private readonly ?string $reportingUsername = null,
        private readonly ?string $reportingPassword = null,
        private readonly string $reportingTable = self::DEFAULT_REPORTING_TABLE,
        private readonly string $configFilePath = self::DEFAULT_CONFIG_FILE_PATH
    ) {
    }

    /**
     * @param array<string, mixed>|null $env
     */
    public static function fromEnvironment(?array $env = null): self
    {
        $configFilePath = self::parseConfigFilePath(
            self::env('PHP_TAINT_TRACE_CONFIG_FILE', $env)
        );
        $config = self::loadRuntimeConfigFile($configFilePath);
        $reportingBackend = self::parseReportingBackend(
            self::resolve(
                'PHP_TAINT_TRACE_REPORTING_BACKEND',
                'reporting_backend',
                $env,
                $config
            )
        );

        return new self(
            enabled: self::parseBool(
                self::resolve('PHP_TAINT_TRACE_ENABLED', 'enabled', $env, $config),
                true
            ),
            findingsFilePath: self::parseNullablePath(
                self::resolve('PHP_TAINT_TRACE_FINDINGS_FILE', 'findings_file', $env, $config)
            ),
            emitErrorLog: self::parseBool(
                self::resolve('PHP_TAINT_TRACE_ERROR_LOG', 'error_log', $env, $config),
                true
            ),
            clearFindingsAfterFlush: self::parseBool(
                self::resolve('PHP_TAINT_TRACE_CLEAR_AFTER_FLUSH', 'clear_after_flush', $env, $config),
                true
            ),
            emitCandidates: self::parseBool(
                self::resolve('PHP_TAINT_TRACE_EMIT_CANDIDATES', 'emit_candidates', $env, $config),
                false
            ),
            enableOpcodeHooks: self::parseBool(
                self::resolve('PHP_TAINT_TRACE_ENABLE_OPCODE_HOOKS', 'enable_opcode_hooks', $env, $config),
                false
            ),
            opcodeHookProfile: self::parseOpcodeHookProfile(
                self::resolve('PHP_TAINT_TRACE_OPCODE_HOOK_PROFILE', 'opcode_hook_profile', $env, $config)
            ),
            enableVerifier: self::parseBool(
                self::resolve('PHP_TAINT_TRACE_ENABLE_VERIFIER', 'enable_verifier', $env, $config),
                false
            ),
            verifierRuntimeDir: self::parseRuntimeDir(
                self::resolve('PHP_TAINT_TRACE_VERIFIER_RUNTIME_DIR', 'verifier_runtime_dir', $env, $config)
            ),
            verifierReplayTarget: self::parseVerifierReplayTarget(
                self::resolve('PHP_TAINT_TRACE_VERIFIER_REPLAY_TARGET', 'verifier_replay_target', $env, $config)
            ),
            reportingBackend: $reportingBackend,
            reportingDsn: self::parseReportingDsn(
                $reportingBackend,
                self::resolve('PHP_TAINT_TRACE_REPORTING_DSN', 'reporting_dsn', $env, $config)
            ),
            reportingUsername: self::parseNullableString(
                self::resolve('PHP_TAINT_TRACE_REPORTING_USERNAME', 'reporting_username', $env, $config)
            ),
            reportingPassword: self::parseNullableString(
                self::resolve('PHP_TAINT_TRACE_REPORTING_PASSWORD', 'reporting_password', $env, $config)
            ),
            reportingTable: self::parseReportingTable(
                self::resolve('PHP_TAINT_TRACE_REPORTING_TABLE', 'reporting_table', $env, $config)
            ),
            configFilePath: $configFilePath
        );
    }

    public function enabled(): bool
    {
        return $this->enabled;
    }

    public function findingsFilePath(): ?string
    {
        return $this->findingsFilePath;
    }

    public function emitErrorLog(): bool
    {
        return $this->emitErrorLog;
    }

    public function clearFindingsAfterFlush(): bool
    {
        return $this->clearFindingsAfterFlush;
    }

    public function emitCandidates(): bool
    {
        return $this->emitCandidates;
    }

    public function enableOpcodeHooks(): bool
    {
        return $this->enableOpcodeHooks;
    }

    public function opcodeHookProfile(): string
    {
        return $this->opcodeHookProfile;
    }

    public function enableVerifier(): bool
    {
        return $this->enableVerifier;
    }

    public function verifierRuntimeDir(): string
    {
        return $this->verifierRuntimeDir;
    }

    public function verifierReplayTarget(): string
    {
        return $this->verifierReplayTarget;
    }

    public function reportingBackend(): string
    {
        return $this->reportingBackend;
    }

    public function reportingDsn(): ?string
    {
        return $this->reportingDsn;
    }

    public function reportingUsername(): ?string
    {
        return $this->reportingUsername;
    }

    public function reportingPassword(): ?string
    {
        return $this->reportingPassword;
    }

    public function reportingTable(): string
    {
        return $this->reportingTable;
    }

    public function configFilePath(): string
    {
        return $this->configFilePath;
    }

    /**
     * @param array<string, mixed>|null $env
     */
    private static function env(string $name, ?array $env): ?string
    {
        if ($env !== null && array_key_exists($name, $env) && $env[$name] !== null) {
            return (string) $env[$name];
        }

        $value = getenv($name);
        if ($value !== false) {
            return (string) $value;
        }

        if (isset($_SERVER[$name])) {
            return (string) $_SERVER[$name];
        }

        return null;
    }

    /**
     * @param array<string, mixed>|null $env
     * @param array<string, mixed> $config
     */
    private static function resolve(string $envName, string $configKey, ?array $env, array $config): mixed
    {
        $envValue = self::env($envName, $env);
        if ($envValue !== null) {
            return $envValue;
        }

        if (array_key_exists($configKey, $config)) {
            return $config[$configKey];
        }

        if (array_key_exists($envName, $config)) {
            return $config[$envName];
        }

        return null;
    }

    private static function parseNullablePath(mixed $value): ?string
    {
        $resolved = self::normalizeScalarToString($value);
        if ($resolved === null) {
            return null;
        }

        $trimmed = trim($resolved);
        return $trimmed === '' ? null : $trimmed;
    }

    private static function parseNullableString(mixed $value): ?string
    {
        return self::parseNullablePath($value);
    }

    private static function parseBool(mixed $value, bool $default): bool
    {
        if ($value === null) {
            return $default;
        }

        if (is_bool($value)) {
            return $value;
        }

        if (is_int($value) || is_float($value)) {
            return ((int) $value) !== 0;
        }

        if (!is_scalar($value)) {
            return $default;
        }

        return match (strtolower(trim((string) $value))) {
            '1', 'true', 'yes', 'on' => true,
            '0', 'false', 'no', 'off' => false,
            default => $default,
        };
    }

    private static function parseOpcodeHookProfile(mixed $value): string
    {
        $resolved = self::normalizeScalarToString($value);
        if ($resolved === null) {
            return self::OPCODE_HOOK_PROFILE_SAFE;
        }

        return match (strtolower(trim($resolved))) {
            self::OPCODE_HOOK_PROFILE_SAFE => self::OPCODE_HOOK_PROFILE_SAFE,
            self::OPCODE_HOOK_PROFILE_FULL => self::OPCODE_HOOK_PROFILE_FULL,
            default => self::OPCODE_HOOK_PROFILE_SAFE,
        };
    }

    private static function parseRuntimeDir(mixed $value): string
    {
        $resolved = self::normalizeScalarToString($value);
        if ($resolved === null) {
            return '.php_taint_trace_runtime/verifier';
        }

        $trimmed = trim($resolved);
        if ($trimmed === '') {
            return '.php_taint_trace_runtime/verifier';
        }

        return $trimmed;
    }

    private static function parseVerifierReplayTarget(mixed $value): string
    {
        $resolved = self::normalizeScalarToString($value);
        if ($resolved === null) {
            return self::VERIFIER_REPLAY_TARGET_LOCAL;
        }

        return match (strtolower(trim($resolved))) {
            self::VERIFIER_REPLAY_TARGET_LOCAL => self::VERIFIER_REPLAY_TARGET_LOCAL,
            self::VERIFIER_REPLAY_TARGET_REMOTE_LAB => self::VERIFIER_REPLAY_TARGET_REMOTE_LAB,
            default => self::VERIFIER_REPLAY_TARGET_LOCAL,
        };
    }

    private static function parseReportingBackend(mixed $value): string
    {
        $resolved = self::normalizeScalarToString($value);
        if ($resolved === null) {
            return self::REPORTING_BACKEND_JSONL;
        }

        return match (strtolower(trim($resolved))) {
            self::REPORTING_BACKEND_JSONL => self::REPORTING_BACKEND_JSONL,
            self::REPORTING_BACKEND_SQLITE => self::REPORTING_BACKEND_SQLITE,
            self::REPORTING_BACKEND_PDO => self::REPORTING_BACKEND_PDO,
            default => self::REPORTING_BACKEND_JSONL,
        };
    }

    private static function parseReportingDsn(string $backend, mixed $value): ?string
    {
        $resolved = self::parseNullableString($value);
        if ($resolved !== null) {
            if (
                $backend === self::REPORTING_BACKEND_SQLITE &&
                !str_starts_with(strtolower($resolved), 'sqlite:')
            ) {
                return 'sqlite:' . $resolved;
            }

            return $resolved;
        }

        if ($backend === self::REPORTING_BACKEND_SQLITE) {
            return 'sqlite:.php_taint_trace_runtime/reporting.sqlite3';
        }

        return null;
    }

    private static function parseReportingTable(mixed $value): string
    {
        $resolved = self::parseNullableString($value);
        if ($resolved === null) {
            return self::DEFAULT_REPORTING_TABLE;
        }

        return preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/', $resolved) === 1
            ? $resolved
            : self::DEFAULT_REPORTING_TABLE;
    }

    private static function parseConfigFilePath(?string $value): string
    {
        $resolved = self::parseNullablePath($value);
        if ($resolved === null) {
            return self::DEFAULT_CONFIG_FILE_PATH;
        }

        return $resolved;
    }

    /**
     * @return array<string, mixed>
     */
    private static function loadRuntimeConfigFile(string $path): array
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
            error_log('[php_taint_trace] unable to parse runtime config file: ' . $path);
            return array();
        }

        if (isset($decoded['runtime']) && is_array($decoded['runtime'])) {
            return $decoded['runtime'];
        }

        return $decoded;
    }

    private static function normalizeScalarToString(mixed $value): ?string
    {
        if ($value === null) {
            return null;
        }

        if (!is_scalar($value)) {
            return null;
        }

        return (string) $value;
    }
}
