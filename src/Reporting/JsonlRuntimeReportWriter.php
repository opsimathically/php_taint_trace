<?php

declare(strict_types=1);

namespace PhpTaintTrace\Reporting;

final class JsonlRuntimeReportWriter implements RuntimeReportWriterInterface
{
    public function __construct(
        private readonly ?string $filePath,
        private readonly bool $emitErrorLog
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

        if ($this->filePath !== null) {
            $directory = dirname($this->filePath);
            if (!is_dir($directory)) {
                @mkdir($directory, 0775, true);
            }

            @file_put_contents($this->filePath, $json . PHP_EOL, FILE_APPEND | LOCK_EX);
        }

        if ($this->emitErrorLog) {
            error_log('[php_taint_trace] ' . $json);
        }
    }
}

