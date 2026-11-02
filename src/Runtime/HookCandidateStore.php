<?php

declare(strict_types=1);

namespace PhpTaintTrace\Runtime;

use PhpTaintTrace\Verification\Model\DetectorCandidate;

final class HookCandidateStore
{
    /**
     * @var DetectorCandidate[]
     */
    private array $candidates = array();

    /**
     * @param DetectorCandidate[] $candidates
     */
    public function appendMany(array $candidates): void
    {
        foreach ($candidates as $candidate) {
            $this->candidates[] = $candidate;
        }
    }

    public function append(DetectorCandidate $candidate): void
    {
        $this->candidates[] = $candidate;
    }

    /**
     * @return DetectorCandidate[]
     */
    public function all(): array
    {
        return $this->candidates;
    }

    public function clear(): void
    {
        $this->candidates = array();
    }
}
