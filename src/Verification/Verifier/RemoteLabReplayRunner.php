<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Verifier;

final class RemoteLabReplayRunner implements ReplayRunnerInterface
{
    /**
     * @param array<string, int> $categoryPortMap
     */
    public function __construct(
        private readonly string $host,
        private readonly array $categoryPortMap = array(
            'xss' => 19081,
            'rce' => 19082,
            'file' => 19083,
            'ssrf' => 19084,
            'sqli' => 19085,
            'idor' => 19086,
            'xxe' => 19087,
        ),
        private readonly int $timeoutSeconds = 4
    ) {
    }

    public function replay(ReplayRequest $request): ReplayResult
    {
        $base = $this->baseUrlForCategory($request->sinkCategory());
        $runner = new LocalReplayRunner($base, $this->timeoutSeconds);

        return $runner->replay($request);
    }

    public function callbackBaseUrl(): string
    {
        return $this->baseUrlForCategory('xss');
    }

    private function baseUrlForCategory(string $category): string
    {
        $resolvedCategory = $category;
        if (!array_key_exists($resolvedCategory, $this->categoryPortMap)) {
            $resolvedCategory = 'rce';
        }

        $port = (int) $this->categoryPortMap[$resolvedCategory];
        return sprintf('http://%s:%d', $this->host, $port);
    }
}
