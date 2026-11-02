<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Verifier;

interface ReplayRunnerInterface
{
    public function replay(ReplayRequest $request): ReplayResult;

    public function callbackBaseUrl(): string;
}
