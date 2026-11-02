<?php

declare(strict_types=1);

namespace PhpTaintTrace\Instrumentation;

final class BaselineHookPlan
{
    /**
     * @var HookDefinition[]
     */
    private array $hooks;

    public function __construct(HookDefinition ...$hooks)
    {
        $this->hooks = $hooks;
    }

    /**
     * @return HookDefinition[]
     */
    public function hooks(): array
    {
        return $this->hooks;
    }

    public function count(): int
    {
        return count($this->hooks);
    }

    /**
     * @return HookDefinition[]
     */
    public function hooksByKind(HookKind $kind): array
    {
        return array_values(array_filter(
            $this->hooks,
            static fn (HookDefinition $hook): bool => $hook->kind() === $kind
        ));
    }
}
