<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Storage;

use PhpTaintTrace\Verification\Model\RiskDecision;

interface DecisionStoreInterface
{
    public function persist(RiskDecision $decision): bool;

    public function decisionsPath(): string;
}
