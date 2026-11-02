<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Model;

enum DecisionTier: string
{
    case CONFIRMED = 'confirmed';
    case HIGH_LIKELIHOOD = 'high_likelihood';
    case REACHABLE_UNVERIFIED = 'reachable_unverified';
    case SUPPRESSED = 'suppressed';
    case INVALID = 'invalid';
}
