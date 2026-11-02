<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Model;

final class DetectorEvidence
{
    /**
     * @param string[] $detectors
     * @param string[] $severities
     * @param string[] $messages
     * @param array<string, mixed> $metadata
     */
    public function __construct(
        private readonly int $findingCount,
        array $detectors,
        array $severities,
        array $messages,
        private readonly array $metadata = array()
    ) {
        $resolvedDetectors = array_values(array_unique($detectors));
        sort($resolvedDetectors);
        $this->detectors = $resolvedDetectors;

        $resolvedSeverities = array_values(array_unique($severities));
        sort($resolvedSeverities);
        $this->severities = $resolvedSeverities;

        $resolvedMessages = array_values(array_unique($messages));
        sort($resolvedMessages);
        $this->messages = $resolvedMessages;
    }

    /**
     * @var string[]
     */
    private readonly array $detectors;

    /**
     * @var string[]
     */
    private readonly array $severities;

    /**
     * @var string[]
     */
    private readonly array $messages;

    public function findingCount(): int
    {
        return $this->findingCount;
    }

    /**
     * @return string[]
     */
    public function detectors(): array
    {
        return $this->detectors;
    }

    /**
     * @return string[]
     */
    public function severities(): array
    {
        return $this->severities;
    }

    /**
     * @return string[]
     */
    public function messages(): array
    {
        return $this->messages;
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
            'finding_count' => $this->findingCount,
            'detectors' => $this->detectors,
            'severities' => $this->severities,
            'messages' => $this->messages,
            'metadata' => $this->metadata,
        );
    }
}
