<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Model;

enum VerificationOutcome: string
{
    case CONFIRMED = 'confirmed';
    case NOT_CONFIRMED = 'not_confirmed';
    case INCONCLUSIVE = 'inconclusive';
    case BLOCKED_BY_POLICY = 'blocked_by_policy';
    case REPLAY_FAILED = 'replay_failed';
}
