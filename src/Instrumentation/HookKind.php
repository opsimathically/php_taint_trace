<?php

declare(strict_types=1);

namespace PhpTaintTrace\Instrumentation;

enum HookKind: string
{
    case FUNCTION = 'function';
    case METHOD = 'method';
    case OPCODE = 'opcode';
}
