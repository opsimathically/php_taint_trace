<?php

declare(strict_types=1);

namespace PhpTaintTrace\Instrumentation;

final class HookDefinition
{
    /**
     * @param array<string, mixed> $metadata
     */
    public function __construct(
        private readonly string $id,
        private readonly HookKind $kind,
        private readonly string $target,
        private readonly HookPhase $phase = HookPhase::REPLACE,
        private readonly array $metadata = array()
    ) {
    }

    /**
     * @param array<string, mixed> $metadata
     */
    public static function function(
        string $id,
        string $functionName,
        HookPhase $phase = HookPhase::REPLACE,
        array $metadata = array()
    ): self {
        return new self($id, HookKind::FUNCTION, $functionName, $phase, $metadata);
    }

    /**
     * @param array<string, mixed> $metadata
     */
    public static function method(
        string $id,
        string $className,
        string $methodName,
        HookPhase $phase = HookPhase::REPLACE,
        array $metadata = array()
    ): self {
        return new self(
            $id,
            HookKind::METHOD,
            sprintf('%s::%s', $className, $methodName),
            $phase,
            $metadata
        );
    }

    /**
     * @param array<string, mixed> $metadata
     */
    public static function opcode(
        string $id,
        string $opcode,
        HookPhase $phase = HookPhase::BEFORE,
        array $metadata = array()
    ): self {
        return new self($id, HookKind::OPCODE, $opcode, $phase, $metadata);
    }

    public function id(): string
    {
        return $this->id;
    }

    public function kind(): HookKind
    {
        return $this->kind;
    }

    public function target(): string
    {
        return $this->target;
    }

    public function phase(): HookPhase
    {
        return $this->phase;
    }

    /**
     * @return array<string, mixed>
     */
    public function metadata(): array
    {
        return $this->metadata;
    }
}
