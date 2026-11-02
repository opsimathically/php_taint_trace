<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Oracle;

use PhpTaintTrace\Verification\Model\VerificationJob;

interface OracleInterface
{
    public function supports(VerificationJob $job): bool;

    public function verify(OracleContext $context): OracleDecision;
}
