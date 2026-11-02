<?php

declare(strict_types=1);

namespace PhpTaintTrace\Instrumentation;

final class InstrumentationCapabilities
{
    public function __construct(
        private readonly bool $functionHooks,
        private readonly bool $methodHooks,
        private readonly bool $opcodeHooks,
        private readonly bool $taintTracking,
        private readonly bool $symbolRenaming
    ) {
    }

    public static function full(): self
    {
        return new self(true, true, true, true, true);
    }

    public static function functionAndMethodOnly(): self
    {
        return new self(true, true, false, true, false);
    }

    public static function none(): self
    {
        return new self(false, false, false, false, false);
    }

    public function functionHooks(): bool
    {
        return $this->functionHooks;
    }

    public function methodHooks(): bool
    {
        return $this->methodHooks;
    }

    public function opcodeHooks(): bool
    {
        return $this->opcodeHooks;
    }

    public function taintTracking(): bool
    {
        return $this->taintTracking;
    }

    public function symbolRenaming(): bool
    {
        return $this->symbolRenaming;
    }

    public function supports(HookKind $kind): bool
    {
        return match ($kind) {
            HookKind::FUNCTION => $this->functionHooks,
            HookKind::METHOD => $this->methodHooks,
            HookKind::OPCODE => $this->opcodeHooks,
        };
    }
}
