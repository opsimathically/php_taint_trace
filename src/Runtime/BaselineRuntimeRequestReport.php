<?php

declare(strict_types=1);

namespace PhpTaintTrace\Runtime;

final class BaselineRuntimeRequestReport
{
    /**
     * @var string[]
     */
    private array $seededSources;

    /**
     * @param string[] $seededSources
     */
    public function __construct(
        private readonly BaselineRuntimeBootstrapReport $bootstrapReport,
        array $seededSources,
        private readonly bool $bootstrappedNow
    ) {
        $this->seededSources = array_values($seededSources);
    }

    public function bootstrapReport(): BaselineRuntimeBootstrapReport
    {
        return $this->bootstrapReport;
    }

    /**
     * @return string[]
     */
    public function seededSources(): array
    {
        return $this->seededSources;
    }

    public function seededSourceCount(): int
    {
        return count($this->seededSources);
    }

    public function bootstrappedNow(): bool
    {
        return $this->bootstrappedNow;
    }
}
