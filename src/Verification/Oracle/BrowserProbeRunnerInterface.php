<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Oracle;

interface BrowserProbeRunnerInterface
{
    public function probe(BrowserProbeRequest $request): BrowserProbeResult;
}

