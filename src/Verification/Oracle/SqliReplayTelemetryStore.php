<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Oracle;

final class SqliReplayTelemetryStore
{
    private const DEFAULT_DIRECTORY = '/tmp/php_taint_trace_sqli_replay';

    public static function directory(): string
    {
        $configured = getenv('PHP_TAINT_TRACE_SQLI_REPLAY_DIR');
        if (is_string($configured)) {
            $trimmed = trim($configured);
            if ($trimmed !== '') {
                return $trimmed;
            }
        }

        return self::DEFAULT_DIRECTORY;
    }

    public static function isValidReplayId(string $replayId): bool
    {
        return preg_match('/^[A-Za-z0-9._:-]{8,128}$/', $replayId) === 1;
    }

    public static function append(string $replayId, array $payload): void
    {
        if (!self::isValidReplayId($replayId)) {
            return;
        }

        $directory = self::directory();
        if (!is_dir($directory)) {
            @mkdir($directory, 0775, true);
        }

        $path = self::pathForReplayId($replayId);
        if ($path === null) {
            return;
        }

        $json = json_encode($payload, JSON_UNESCAPED_SLASHES);
        if (!is_string($json)) {
            return;
        }

        @file_put_contents($path, $json . PHP_EOL, FILE_APPEND | LOCK_EX);
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    public static function read(string $replayId): array
    {
        $path = self::pathForReplayId($replayId);
        if ($path === null || !is_file($path)) {
            return array();
        }

        $lines = @file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (!is_array($lines)) {
            return array();
        }

        $rows = array();
        foreach ($lines as $line) {
            if (!is_string($line)) {
                continue;
            }

            $parsed = json_decode($line, true);
            if (!is_array($parsed)) {
                continue;
            }

            $rows[] = $parsed;
        }

        return $rows;
    }

    public static function delete(string $replayId): void
    {
        $path = self::pathForReplayId($replayId);
        if ($path === null || !is_file($path)) {
            return;
        }

        @unlink($path);
    }

    private static function pathForReplayId(string $replayId): ?string
    {
        if (!self::isValidReplayId($replayId)) {
            return null;
        }

        return rtrim(self::directory(), '/') . '/' . $replayId . '.jsonl';
    }
}
