<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Model;

final class CandidateCollection
{
    /**
     * @var DetectorCandidate[]
     */
    private array $candidates;

    public function __construct(DetectorCandidate ...$candidates)
    {
        $this->candidates = array_values($candidates);
    }

    /**
     * @return DetectorCandidate[]
     */
    public function all(): array
    {
        return $this->candidates;
    }

    public function count(): int
    {
        return count($this->candidates);
    }

    public function isEmpty(): bool
    {
        return $this->count() === 0;
    }

    public function first(): ?DetectorCandidate
    {
        return $this->candidates[0] ?? null;
    }

    public function withCandidate(DetectorCandidate $candidate): self
    {
        $next = $this->candidates;
        $next[] = $candidate;

        return new self(...$next);
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    public function toArray(): array
    {
        return array_map(
            static fn (DetectorCandidate $candidate): array => $candidate->toArray(),
            $this->candidates
        );
    }
}
