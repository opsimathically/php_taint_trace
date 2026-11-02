<?php

declare(strict_types=1);

namespace PhpTaintTrace\Model;

enum SinkCategory: string
{
    case RCE = 'rce';
    case SQLI = 'sqli';
    case SSRF = 'ssrf';
    case FILE = 'file';
    case XSS = 'xss';
    case XXE = 'xxe';
    case CALLBACK = 'callback';
    case CUSTOM = 'custom';
}
