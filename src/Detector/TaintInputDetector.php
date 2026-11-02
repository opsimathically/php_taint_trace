<?php

declare(strict_types=1);

namespace PhpTaintTrace\Detector;

use PhpTaintTrace\Contract\DetectorInterface;
use PhpTaintTrace\Model\Finding;
use PhpTaintTrace\Model\SinkInvocation;

final class TaintInputDetector implements DetectorInterface
{
    public function __construct(
        private readonly string $severity = 'debug'
    ) {
    }

    public function name(): string
    {
        return 'taint-input-detector';
    }

    public function detect(SinkInvocation $invocation): ?Finding
    {
        if (!$invocation->hasTaintedInput()) {
            return null;
        }

        return new Finding(
            detector: $this->name(),
            severity: $this->severity,
            message: 'Tainted input reached sink.',
            sinkName: $invocation->sinkName(),
            sinkCategory: $invocation->sinkCategory()
        );
    }
}
