<?php

declare(strict_types=1);

namespace PhpTaintTrace\Reporting;

final class PdoRuntimeReportWriter implements RuntimeReportWriterInterface
{
    private ?\PDO $pdo = null;
    private bool $schemaReady = false;

    public function __construct(
        private readonly string $dsn,
        private readonly ?string $username,
        private readonly ?string $password,
        private readonly string $table
    ) {
    }

    /**
     * @param array<string, mixed> $payload
     */
    public function write(array $payload): void
    {
        $json = json_encode($payload, JSON_UNESCAPED_SLASHES);
        if (!is_string($json)) {
            return;
        }

        $pdo = $this->pdo();
        $this->ensureSchema($pdo);

        $stmt = $pdo->prepare(
            sprintf(
                'INSERT INTO %s (created_at, sapi, request_method, request_uri, findings_count, candidates_count, payload_json) VALUES (:created_at, :sapi, :request_method, :request_uri, :findings_count, :candidates_count, :payload_json)',
                $this->table
            )
        );

        if ($stmt === false) {
            throw new \RuntimeException('failed to prepare report insert statement');
        }

        $findings = $payload['findings'] ?? null;
        $candidates = $payload['candidates'] ?? null;

        $stmt->bindValue(':created_at', (string) ($payload['timestamp'] ?? gmdate('c')));
        $stmt->bindValue(':sapi', self::nullableString($payload['sapi'] ?? null));
        $stmt->bindValue(':request_method', self::nullableString($payload['request_method'] ?? null));
        $stmt->bindValue(':request_uri', self::nullableString($payload['request_uri'] ?? null));
        $stmt->bindValue(':findings_count', is_array($findings) ? count($findings) : 0, \PDO::PARAM_INT);
        $stmt->bindValue(':candidates_count', is_array($candidates) ? count($candidates) : 0, \PDO::PARAM_INT);
        $stmt->bindValue(':payload_json', $json);
        $stmt->execute();
    }

    private function pdo(): \PDO
    {
        if ($this->pdo instanceof \PDO) {
            return $this->pdo;
        }

        $pdo = new \PDO($this->dsn, $this->username, $this->password, array(
            \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
            \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
        ));
        $this->pdo = $pdo;
        return $pdo;
    }

    private function ensureSchema(\PDO $pdo): void
    {
        if ($this->schemaReady) {
            return;
        }

        if (preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/', $this->table) !== 1) {
            throw new \RuntimeException('invalid reporting table name');
        }

        $driver = (string) $pdo->getAttribute(\PDO::ATTR_DRIVER_NAME);
        $createSql = match ($driver) {
            'sqlite' => sprintf(
                'CREATE TABLE IF NOT EXISTS %s (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, sapi TEXT NULL, request_method TEXT NULL, request_uri TEXT NULL, findings_count INTEGER NOT NULL, candidates_count INTEGER NOT NULL, payload_json TEXT NOT NULL)',
                $this->table
            ),
            'mysql' => sprintf(
                'CREATE TABLE IF NOT EXISTS %s (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY, created_at TEXT NOT NULL, sapi TEXT NULL, request_method TEXT NULL, request_uri TEXT NULL, findings_count INT NOT NULL, candidates_count INT NOT NULL, payload_json LONGTEXT NOT NULL)',
                $this->table
            ),
            'pgsql' => sprintf(
                'CREATE TABLE IF NOT EXISTS %s (id BIGSERIAL PRIMARY KEY, created_at TEXT NOT NULL, sapi TEXT NULL, request_method TEXT NULL, request_uri TEXT NULL, findings_count INTEGER NOT NULL, candidates_count INTEGER NOT NULL, payload_json TEXT NOT NULL)',
                $this->table
            ),
            default => null,
        };

        if ($createSql === null) {
            throw new \RuntimeException('unsupported PDO driver for reporting: ' . $driver);
        }

        $pdo->exec($createSql);
        $this->schemaReady = true;
    }

    private static function nullableString(mixed $value): ?string
    {
        if ($value === null) {
            return null;
        }

        if (!is_scalar($value)) {
            return null;
        }

        $resolved = trim((string) $value);
        return $resolved === '' ? null : $resolved;
    }
}

