<?php

declare(strict_types=1);

namespace PhpTaintTrace\Core;

final class TaintMetadata
{
    /**
     * @param string[] $sources
     */
    private function __construct(
        private readonly bool $tainted,
        private readonly array $sources
    ) {
    }

    public static function clean(): self
    {
        return new self(false, array());
    }

    public static function fromSource(string $source): self
    {
        return new self(true, array($source));
    }

    public function isTainted(): bool
    {
        return $this->tainted;
    }

    /**
     * @return string[]
     */
    public function sources(): array
    {
        return $this->sources;
    }

    public function merge(self $other): self
    {
        if (!$this->tainted && !$other->tainted) {
            return self::clean();
        }

        $sources = array_values(array_unique(array_merge($this->sources, $other->sources)));
        sort($sources);

        return new self(true, $sources);
    }
}
