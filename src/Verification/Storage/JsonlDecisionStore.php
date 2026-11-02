<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Storage;

use PhpTaintTrace\Verification\Model\RiskDecision;
use RuntimeException;

final class JsonlDecisionStore implements DecisionStoreInterface
{
    private readonly string $decisionsPath;
    private readonly string $lockPath;

    public function __construct(
        private readonly string $runtimeDirectory
    ) {
        $this->decisionsPath = $this->runtimeDirectory . '/decisions.jsonl';
        $this->lockPath = $this->runtimeDirectory . '/decisions.lock';
        $this->ensureLayout();
    }

    public function persist(RiskDecision $decision): bool
    {
        return $this->withLock(function () use ($decision): bool {
            if ($this->dedupExistsLocked($decision->dedupKey())) {
                return false;
            }

            $this->appendJsonLine($this->decisionsPath, $decision->toArray());
            return true;
        });
    }

    public function decisionsPath(): string
    {
        return $this->decisionsPath;
    }

    private function ensureLayout(): void
    {
        if (!is_dir($this->runtimeDirectory) && !@mkdir($this->runtimeDirectory, 0775, true) && !is_dir($this->runtimeDirectory)) {
            throw new RuntimeException(sprintf('Failed to create decision runtime directory: %s', $this->runtimeDirectory));
        }

        foreach (array($this->decisionsPath, $this->lockPath) as $path) {
            if (!is_file($path)) {
                @touch($path);
            }
        }
    }

    private function dedupExistsLocked(string $dedupKey): bool
    {
        foreach ($this->readJsonLines($this->decisionsPath) as $payload) {
            if ((string) ($payload['dedup_key'] ?? '') === $dedupKey) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    private function readJsonLines(string $path): array
    {
        $lines = @file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (!is_array($lines)) {
            return array();
        }

        $payloads = array();
        foreach ($lines as $line) {
            $decoded = json_decode($line, true);
            if (!is_array($decoded)) {
                continue;
            }

            $payloads[] = $decoded;
        }

        return $payloads;
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function appendJsonLine(string $path, array $payload): void
    {
        $encoded = json_encode($payload, JSON_UNESCAPED_SLASHES);
        if (!is_string($encoded)) {
            throw new RuntimeException('Failed to encode decision payload.');
        }

        @file_put_contents($path, $encoded . PHP_EOL, FILE_APPEND | LOCK_EX);
    }

    /**
     * @template T
     * @param callable(): T $callback
     * @return T
     */
    private function withLock(callable $callback): mixed
    {
        $handle = fopen($this->lockPath, 'c+');
        if (!is_resource($handle)) {
            throw new RuntimeException(sprintf('Unable to open decision lock file: %s', $this->lockPath));
        }

        try {
            if (!flock($handle, LOCK_EX)) {
                throw new RuntimeException('Unable to acquire decision store lock.');
            }

            return $callback();
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }
}
