<?php

declare(strict_types=1);

namespace PhpTaintTrace\Runtime;

use PhpTaintTrace\Contract\DetectorInterface;
use PhpTaintTrace\Model\Finding;
use PhpTaintTrace\Model\SinkInvocation;

final class DetectorPipeline
{
    /**
     * @var DetectorInterface[]
     */
    private array $detectors;

    public function __construct(DetectorInterface ...$detectors)
    {
        $this->detectors = $detectors;
    }

    public function addDetector(DetectorInterface $detector): void
    {
        $this->detectors[] = $detector;
    }

    /**
     * @return Finding[]
     */
    public function detect(SinkInvocation $invocation): array
    {
        $findings = array();
        foreach ($this->detectors as $detector) {
            $finding = $detector->detect($invocation);
            if ($finding !== null) {
                $findings[] = $finding;
            }
        }

        return $findings;
    }
}
