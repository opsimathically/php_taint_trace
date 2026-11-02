<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit\Verification;

use PhpTaintTrace\Core\TaintedValue;
use PhpTaintTrace\Model\Finding;
use PhpTaintTrace\Model\SinkCategory;
use PhpTaintTrace\Model\SinkInvocation;
use PhpTaintTrace\Verification\Detector\CandidateBuilder;
use PhpTaintTrace\Verification\Model\EnvironmentEvidence;
use PhpTaintTrace\Verification\Model\ReasonCode;
use PhpTaintTrace\Verification\Model\RequestEvidence;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

final class CandidateBuilderTest extends TestCase
{
    public function testBuildIncludesTaintAndDetectorReasonCodes(): void
    {
        $builder = new CandidateBuilder();

        $candidate = $builder->build(
            new SinkInvocation('system', SinkCategory::RCE, array(
                TaintedValue::tainted('id', '_GET'),
                'ignored',
            ), array(
                'stacktrace' => array(
                    array(
                        'level' => 0,
                        'where' => 'App\\Example->dangerous',
                        'file_uri' => '/var/www/html/index.php',
                        'lineno' => 42,
                        'type' => '->',
                    ),
                ),
            )),
            array(
                new Finding(
                    detector: 'taint-input-detector',
                    severity: 'debug',
                    message: 'Tainted input reached sink.',
                    sinkName: 'system',
                    sinkCategory: SinkCategory::RCE
                ),
                new Finding(
                    detector: 'payload-keyword-detector',
                    severity: 'error',
                    message: 'Payload keyword "xtanzi" detected in sink input.',
                    sinkName: 'system',
                    sinkCategory: SinkCategory::RCE
                ),
            ),
            new RequestEvidence('2026-04-22T00:00:00+00:00', 'cli-server', 'GET', '/?cmd=id'),
            new EnvironmentEvidence('8.3.6', 'cli-server', array('xmark'))
        );

        $reasonCodes = array_map(
            static fn (ReasonCode $reasonCode): string => $reasonCode->value,
            $candidate->reasonCodes()
        );

        self::assertContains('DETECTOR_TAINT_INPUT', $reasonCodes);
        self::assertContains('DETECTOR_PAYLOAD_KEYWORD', $reasonCodes);
        self::assertContains('TAINT_SOURCE_PRESENT', $reasonCodes);
        self::assertContains('SINK_ARGUMENT_ROLE_PRIMARY', $reasonCodes);
        self::assertContains('CATEGORY_RCE', $reasonCodes);

        self::assertTrue($candidate->authorizationEvidence()->isPartial());
        self::assertSame(array(0), $candidate->taintEvidence()->taintedArgumentIndexes());
        self::assertSame(array('_GET'), $candidate->taintEvidence()->sourceFamilies());
        self::assertSame(2, $candidate->detectorEvidence()->findingCount());
        self::assertSame(
            array(
                array(
                    'level' => 0,
                    'where' => 'App\\Example->dangerous',
                    'file_uri' => '/var/www/html/index.php',
                    'lineno' => 42,
                    'type' => '->',
                ),
            ),
            $candidate->sinkEvidence()->metadata()['stacktrace'] ?? array()
        );
    }

    public function testBuildCapturesAllowlistedRequestHeadersAndCookieKeysInRequestEvidence(): void
    {
        $previousServer = $_SERVER;
        $previousCookie = $_COOKIE;
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['REQUEST_URI'] = '/?cmd=id';
        $_SERVER['HTTP_USER_AGENT'] = 'ptt-test';
        $_SERVER['HTTP_ACCEPT_LANGUAGE'] = 'en-US';
        $_SERVER['HTTP_AUTHORIZATION'] = 'secret-should-not-pass';
        $_COOKIE = array(
            'PHPSESSID' => 'secret',
            'csrftoken' => 'secret2',
        );

        try {
            $builder = new CandidateBuilder();
            $candidate = $builder->build(
                new SinkInvocation('system', SinkCategory::RCE, array(
                    TaintedValue::tainted('id', '_GET'),
                )),
                array(
                    new Finding(
                        detector: 'taint-input-detector',
                        severity: 'debug',
                        message: 'Tainted input reached sink.',
                        sinkName: 'system',
                        sinkCategory: SinkCategory::RCE
                    ),
                )
            );
        } finally {
            $_SERVER = $previousServer;
            $_COOKIE = $previousCookie;
        }

        $metadata = $candidate->requestEvidence()->metadata();
        self::assertSame('ptt-test', $metadata['request_headers']['user-agent'] ?? null);
        self::assertSame('en-US', $metadata['request_headers']['accept-language'] ?? null);
        self::assertArrayNotHasKey('authorization', $metadata['request_headers'] ?? array());
        self::assertSame(array('PHPSESSID', 'csrftoken'), $metadata['cookie_keys'] ?? array());
    }

    public function testBuildDoesNotFatalWhenSuperglobalsAreFrameworkWrappers(): void
    {
        $previousServer = $_SERVER;
        $previousCookie = $_COOKIE;
        $previousPost = $_POST;
        $_SERVER = (object) array();
        $_COOKIE = (object) array();
        $_POST = (object) array();

        try {
            $builder = new CandidateBuilder();
            $candidate = $builder->build(
                new SinkInvocation('system', SinkCategory::RCE, array(
                    TaintedValue::tainted('id', '_GET'),
                )),
                array(
                    new Finding(
                        detector: 'taint-input-detector',
                        severity: 'debug',
                        message: 'Tainted input reached sink.',
                        sinkName: 'system',
                        sinkCategory: SinkCategory::RCE
                    ),
                )
            );
        } finally {
            $_SERVER = $previousServer;
            $_COOKIE = $previousCookie;
            $_POST = $previousPost;
        }

        self::assertSame(array(), $candidate->requestEvidence()->metadata()['request_headers'] ?? null);
        self::assertSame(array(), $candidate->requestEvidence()->metadata()['cookie_keys'] ?? null);
        self::assertNull($candidate->requestEvidence()->requestMethod());
        self::assertNull($candidate->requestEvidence()->requestUri());
    }

    public function testRequestBodyFormatRecognizesJsonContentType(): void
    {
        $builder = new CandidateBuilder();
        $reflected = new ReflectionClass($builder);

        $requestBodyFormat = $reflected->getMethod('requestBodyFormat');
        $requestBodyFormat->setAccessible(true);

        $headers = array('content-type' => 'application/json; charset=utf-8');

        self::assertSame('json', $requestBodyFormat->invoke($builder, $headers));
    }
}
