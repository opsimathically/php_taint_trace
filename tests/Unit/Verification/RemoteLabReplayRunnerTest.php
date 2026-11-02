<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit\Verification;

use PhpTaintTrace\Verification\Verifier\RemoteLabReplayRunner;
use PhpTaintTrace\Verification\Verifier\ReplayRequest;
use PHPUnit\Framework\TestCase;

final class RemoteLabReplayRunnerTest extends TestCase
{
    public function testRunnerRoutesKnownCategoriesToConfiguredPorts(): void
    {
        $runner = new RemoteLabReplayRunner(
            '127.0.0.1',
            array(
                'xss' => 21981,
                'rce' => 21982,
                'file' => 21983,
                'ssrf' => 21984,
                'sqli' => 21985,
                'idor' => 21986,
                'xxe' => 21987,
            ),
            timeoutSeconds: 1
        );

        $sqliResult = $runner->replay(ReplayRequest::fromRequestUri('sqli', 'GET', '/sqli?q=1'));
        $idorResult = $runner->replay(ReplayRequest::fromRequestUri('idor', 'GET', '/idor?resource_id=42'));
        $xxeResult = $runner->replay(ReplayRequest::fromRequestUri('xxe', 'GET', '/xxe?xml=%3Croot%3Ehi%3C%2Froot%3E'));

        self::assertStringStartsWith('http://127.0.0.1:21985', (string) ($sqliResult->metadata()['url'] ?? ''));
        self::assertStringStartsWith('http://127.0.0.1:21986', (string) ($idorResult->metadata()['url'] ?? ''));
        self::assertStringStartsWith('http://127.0.0.1:21987', (string) ($xxeResult->metadata()['url'] ?? ''));
    }

    public function testRunnerFallsBackToRcePortForUnknownCategory(): void
    {
        $runner = new RemoteLabReplayRunner(
            '127.0.0.1',
            array(
                'xss' => 22981,
                'rce' => 22982,
            ),
            timeoutSeconds: 1
        );

        $result = $runner->replay(ReplayRequest::fromRequestUri('unknown', 'GET', '/?x=1'));
        self::assertStringStartsWith('http://127.0.0.1:22982', (string) ($result->metadata()['url'] ?? ''));
        self::assertSame('http://127.0.0.1:22981', $runner->callbackBaseUrl());
    }
}
