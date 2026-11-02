<?php

declare(strict_types=1);

namespace PhpTaintTrace\Detector;

use PhpTaintTrace\Contract\DetectorInterface;
use PhpTaintTrace\Model\Finding;
use PhpTaintTrace\Model\SinkInvocation;

final class PayloadKeywordDetector implements DetectorInterface
{
    public function __construct(
        private readonly string $keyword = 'xtanzi',
        private readonly string $severity = 'error'
    ) {
    }

    public function name(): string
    {
        return 'payload-keyword-detector';
    }

    public function detect(SinkInvocation $invocation): ?Finding
    {
        foreach ($invocation->stringArguments() as $argument) {
            if (stripos($argument, $this->keyword) !== false) {
                return new Finding(
                    detector: $this->name(),
                    severity: $this->severity,
                    message: sprintf('Payload keyword "%s" detected in sink input.', $this->keyword),
                    sinkName: $invocation->sinkName(),
                    sinkCategory: $invocation->sinkCategory(),
                    metadata: array('keyword' => $this->keyword)
                );
            }
        }

        return null;
    }
}
