<?php

declare(strict_types=1);

namespace PhpTaintTrace\Instrumentation;

enum HookPhase: string
{
    case BEFORE = 'before';
    case AFTER = 'after';
    case REPLACE = 'replace';
}
