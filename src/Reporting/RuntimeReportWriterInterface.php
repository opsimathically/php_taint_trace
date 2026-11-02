<?php

declare(strict_types=1);

namespace PhpTaintTrace\Reporting;

interface RuntimeReportWriterInterface
{
    /**
     * @param array<string, mixed> $payload
     */
    public function write(array $payload): void;
}

