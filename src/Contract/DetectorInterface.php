<?php

declare(strict_types=1);

namespace PhpTaintTrace\Contract;

use PhpTaintTrace\Model\Finding;
use PhpTaintTrace\Model\SinkInvocation;

interface DetectorInterface
{
    public function name(): string;

    public function detect(SinkInvocation $invocation): ?Finding;
}
