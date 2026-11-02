<?php

declare(strict_types=1);

namespace PhpTaintTrace\Runtime;

use PhpTaintTrace\Instrumentation\InstrumentationBootstrapReport;

final class BaselineRuntimeBootstrapReport
{
    /**
     * @var array<string, InstrumentationBootstrapReport>
     */
    private array $sliceReports = array();

    public function addSliceReport(string $sliceName, InstrumentationBootstrapReport $report): void
    {
        $this->sliceReports[$sliceName] = $report;
    }

    /**
     * @return array<string, InstrumentationBootstrapReport>
     */
    public function sliceReports(): array
    {
        return $this->sliceReports;
    }

    public function registeredCount(): int
    {
        $count = 0;
        foreach ($this->sliceReports as $report) {
            $count += $report->registeredCount();
        }

        return $count;
    }

    public function skippedCount(): int
    {
        $count = 0;
        foreach ($this->sliceReports as $report) {
            $count += $report->skippedCount();
        }

        return $count;
    }

    /**
     * @return array<string, array<string, string>>
     */
    public function skippedBySlice(): array
    {
        $result = array();
        foreach ($this->sliceReports as $sliceName => $report) {
            $result[$sliceName] = $report->skippedHookReasons();
        }

        return $result;
    }
}
