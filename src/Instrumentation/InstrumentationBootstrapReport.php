<?php

declare(strict_types=1);

namespace PhpTaintTrace\Instrumentation;

final class InstrumentationBootstrapReport
{
    /**
     * @var string[]
     */
    private array $registeredHookIds = array();

    /**
     * @var array<string, string>
     */
    private array $skippedHookReasons = array();

    public function __construct(private readonly string $backendName)
    {
    }

    public function backendName(): string
    {
        return $this->backendName;
    }

    public function register(HookDefinition $hook): void
    {
        $this->registeredHookIds[] = $hook->id();
    }

    public function skip(HookDefinition $hook, string $reason): void
    {
        $this->skippedHookReasons[$hook->id()] = $reason;
    }

    /**
     * @return string[]
     */
    public function registeredHookIds(): array
    {
        return $this->registeredHookIds;
    }

    /**
     * @return array<string, string>
     */
    public function skippedHookReasons(): array
    {
        return $this->skippedHookReasons;
    }

    public function registeredCount(): int
    {
        return count($this->registeredHookIds);
    }

    public function skippedCount(): int
    {
        return count($this->skippedHookReasons);
    }
}
