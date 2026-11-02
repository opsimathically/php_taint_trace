<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit;

use PhpTaintTrace\Instrumentation\Backend\ArrayInstrumentationBackend;
use PhpTaintTrace\Instrumentation\RequestTaintSeeder;
use PHPUnit\Framework\TestCase;

final class RequestTaintSeederTest extends TestCase
{
    public function testSeedsLegacyRequestSuperglobalSources(): void
    {
        $backend = new ArrayInstrumentationBackend();
        $seeder = new RequestTaintSeeder($backend);

        $get = array('id' => '1');
        $post = array('name' => 'alice');
        $cookie = array('sid' => 'abc');
        $files = array('upload' => array('name' => 'x.txt'));
        $request = array('id' => '1', 'name' => 'alice');
        $server = array(
            'HTTP_HOST' => 'example.test',
            'HTTP_X_API_TOKEN' => 'token',
            'REQUEST_METHOD' => 'GET',
        );

        $seededSources = $seeder->seedSuperglobals($get, $post, $cookie, $files, $request, $server);

        $sources = array_map(
            static fn (array $record): ?string => $record['source'],
            $backend->marks()
        );

        self::assertCount(7, $sources);
        self::assertContains('_GET', $sources);
        self::assertContains('_POST', $sources);
        self::assertContains('_COOKIE', $sources);
        self::assertContains('_FILES', $sources);
        self::assertContains('_REQUEST', $sources);
        self::assertContains('_SERVER[HTTP_HOST]', $sources);
        self::assertContains('_SERVER[HTTP_X_API_TOKEN]', $sources);
        self::assertNotContains('_SERVER[REQUEST_METHOD]', $sources);

        self::assertSame(
            array(
                '_GET',
                '_POST',
                '_COOKIE',
                '_FILES',
                '_REQUEST',
                '_SERVER[HTTP_HOST]',
                '_SERVER[HTTP_X_API_TOKEN]',
            ),
            $seededSources
        );
    }
}
