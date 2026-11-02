<?php

declare(strict_types=1);

namespace PhpTaintTrace\Reporting;

use PhpTaintTrace\Runtime\AppRuntimeConfig;

final class RuntimeReportWriterFactory
{
    public static function fromConfig(AppRuntimeConfig $config): RuntimeReportWriterInterface
    {
        $backend = $config->reportingBackend();
        if ($backend === 'jsonl') {
            return new JsonlRuntimeReportWriter(
                $config->findingsFilePath(),
                $config->emitErrorLog()
            );
        }

        $dsn = $config->reportingDsn();
        if ($backend === 'sqlite' && $dsn !== null && !str_starts_with(strtolower($dsn), 'sqlite:')) {
            $dsn = 'sqlite:' . $dsn;
        }

        if ($dsn === null) {
            return new JsonlRuntimeReportWriter(
                $config->findingsFilePath(),
                $config->emitErrorLog()
            );
        }

        return new PdoRuntimeReportWriter(
            $dsn,
            $config->reportingUsername(),
            $config->reportingPassword(),
            $config->reportingTable()
        );
    }
}
