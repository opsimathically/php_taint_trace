<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit\Verification;

use PhpTaintTrace\Verification\Verifier\ReplayRequest;
use PHPUnit\Framework\TestCase;

final class ReplayRequestTest extends TestCase
{
    public function testReplayRequestMutatesSingleQueryParameterAndPreservesOthers(): void
    {
        $base = ReplayRequest::fromRequestUri('rce', 'GET', '/run?cmd=id&keep=1');
        $mutated = $base->withMutatedQueryParameter('cmd', 'echo nonce', 'positive');

        self::assertSame('/run', $mutated->path());
        self::assertSame('echo nonce', $mutated->queryParams()['cmd']);
        self::assertSame('1', $mutated->queryParams()['keep']);
        self::assertSame('cmd', $mutated->mutatedParameter());
        self::assertSame('positive', $mutated->payloadLabel());
    }

    public function testReplayRequestRoundTripIncludesTransportContext(): void
    {
        $request = ReplayRequest::fromArray(array(
            'sink_category' => 'ssrf',
            'method' => 'GET',
            'path' => '/ssrf',
            'query_params' => array('url' => 'http://127.0.0.1'),
            'headers' => array(
                'User-Agent' => 'ptt-test',
                'x-forwarded-for' => '127.0.0.1',
            ),
            'cookies' => array(
                'PHPSESSID' => 'abcd',
            ),
            'body' => '',
        ));

        self::assertSame('ptt-test', $request->headers()['user-agent'] ?? null);
        self::assertSame('127.0.0.1', $request->headers()['x-forwarded-for'] ?? null);
        self::assertSame('abcd', $request->cookies()['PHPSESSID'] ?? null);
        self::assertSame('', $request->body());

        $roundTrip = ReplayRequest::fromArray($request->toArray());
        self::assertSame($request->headers(), $roundTrip->headers());
        self::assertSame($request->cookies(), $roundTrip->cookies());
        self::assertSame($request->body(), $roundTrip->body());
    }

    public function testReplayRequestMutatesBodyParameterAndPreservesQuery(): void
    {
        $base = ReplayRequest::fromArray(array(
            'sink_category' => 'rce',
            'method' => 'POST',
            'path' => '/run',
            'query_params' => array('mode' => 'exec'),
            'body' => 'cmd=id&keep=1',
        ));

        $mutated = $base->withMutatedBodyParameter('cmd', 'echo nonce', 'positive');

        self::assertSame('POST', $mutated->method());
        self::assertSame('exec', $mutated->queryParams()['mode'] ?? null);
        self::assertSame('echo nonce', $mutated->bodyParams()['cmd'] ?? null);
        self::assertSame('1', $mutated->bodyParams()['keep'] ?? null);
        self::assertSame('body', $mutated->mutatedParameterLocation());
        self::assertSame('cmd', $mutated->mutatedParameter());
        self::assertSame('positive', $mutated->payloadLabel());
        self::assertStringContainsString('cmd=echo+nonce', (string) $mutated->body());
    }

    public function testReplayRequestMutatesNestedJsonBodyParameterAndPreservesContentType(): void
    {
        $base = ReplayRequest::fromArray(array(
            'sink_category' => 'rce',
            'method' => 'POST',
            'path' => '/api/json/rce/system',
            'headers' => array('content-type' => 'application/json'),
            'body' => '{"task":{"command":"id"},"metadata":{"source":"json-lab"}}',
        ));

        self::assertSame('id', $base->bodyParams()['task.command'] ?? null);
        self::assertSame('json-lab', $base->bodyParams()['metadata.source'] ?? null);

        $mutated = $base->withMutatedBodyParameter('task.command', 'echo nonce', 'positive');
        $decoded = json_decode((string) $mutated->body(), true, 512, JSON_THROW_ON_ERROR);

        self::assertSame('application/json', $mutated->headers()['content-type'] ?? null);
        self::assertSame('echo nonce', $mutated->bodyParams()['task.command'] ?? null);
        self::assertSame('body', $mutated->mutatedParameterLocation());
        self::assertSame('task.command', $mutated->mutatedParameter());
        self::assertSame('echo nonce', $decoded['task']['command'] ?? null);
        self::assertSame('json-lab', $decoded['metadata']['source'] ?? null);
    }
}
