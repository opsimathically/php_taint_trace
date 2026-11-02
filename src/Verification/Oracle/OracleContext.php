<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Oracle;

use PhpTaintTrace\Verification\Model\OracleArtifactRef;
use PhpTaintTrace\Verification\Model\VerificationJob;
use PhpTaintTrace\Verification\Verifier\ReplayRunnerInterface;

final class OracleContext
{
    public function __construct(
        private readonly VerificationJob $job,
        private readonly ReplayRunnerInterface $replayRunner,
        private readonly string $artifactDirectory,
        private readonly int $verificationRounds = 2
    ) {
    }

    public function job(): VerificationJob
    {
        return $this->job;
    }

    public function replayRunner(): ReplayRunnerInterface
    {
        return $this->replayRunner;
    }

    public function artifactDirectory(): string
    {
        return $this->artifactDirectory;
    }

    public function verificationRounds(): int
    {
        return $this->verificationRounds > 0 ? $this->verificationRounds : 1;
    }

    /**
     * @param array<string, mixed> $payload
     */
    public function writeArtifact(string $type, array $payload): OracleArtifactRef
    {
        if (!is_dir($this->artifactDirectory)) {
            @mkdir($this->artifactDirectory, 0775, true);
        }

        $fileName = sprintf(
            '%s_%s_%s.json',
            $type,
            preg_replace('/[^a-zA-Z0-9_\-]/', '_', $this->job->jobId()),
            bin2hex(random_bytes(4))
        );
        $path = rtrim($this->artifactDirectory, '/') . '/' . $fileName;

        $encoded = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if (!is_string($encoded)) {
            $encoded = '{"error":"failed to encode artifact"}';
        }

        @file_put_contents($path, $encoded . PHP_EOL);

        return new OracleArtifactRef(
            type: $type,
            path: $path,
            metadata: array('bytes' => @filesize($path) ?: 0)
        );
    }
}
