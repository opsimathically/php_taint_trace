<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Model;

final class TaintEvidence
{
    /**
     * @param int[] $taintedArgumentIndexes
     * @param string[] $sourceFamilies
     * @param array<string, mixed> $metadata
     */
    public function __construct(
        private readonly bool $sourcePresent,
        array $taintedArgumentIndexes,
        array $sourceFamilies,
        private readonly array $metadata = array()
    ) {
        $resolvedTaintedArgumentIndexes = array_values($taintedArgumentIndexes);
        sort($resolvedTaintedArgumentIndexes);
        $this->taintedArgumentIndexes = $resolvedTaintedArgumentIndexes;

        $resolvedSourceFamilies = array_values(array_unique($sourceFamilies));
        sort($resolvedSourceFamilies);
        $this->sourceFamilies = $resolvedSourceFamilies;
    }

    /**
     * @var int[]
     */
    private readonly array $taintedArgumentIndexes;

    /**
     * @var string[]
     */
    private readonly array $sourceFamilies;

    public function sourcePresent(): bool
    {
        return $this->sourcePresent;
    }

    /**
     * @return int[]
     */
    public function taintedArgumentIndexes(): array
    {
        return $this->taintedArgumentIndexes;
    }

    /**
     * @return string[]
     */
    public function sourceFamilies(): array
    {
        return $this->sourceFamilies;
    }

    /**
     * @return array<string, mixed>
     */
    public function metadata(): array
    {
        return $this->metadata;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return array(
            'source_present' => $this->sourcePresent,
            'tainted_argument_indexes' => $this->taintedArgumentIndexes,
            'source_families' => $this->sourceFamilies,
            'metadata' => $this->metadata,
        );
    }
}
