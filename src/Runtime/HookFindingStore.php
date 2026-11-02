<?php

declare(strict_types=1);

namespace PhpTaintTrace\Runtime;

use PhpTaintTrace\Model\Finding;

final class HookFindingStore
{
    /**
     * @var Finding[]
     */
    private array $findings = array();

    /**
     * @param Finding[] $findings
     */
    public function appendMany(array $findings): void
    {
        foreach ($findings as $finding) {
            $this->findings[] = $finding;
        }
    }

    /**
     * @return Finding[]
     */
    public function all(): array
    {
        return $this->findings;
    }

    public function clear(): void
    {
        $this->findings = array();
    }
}
