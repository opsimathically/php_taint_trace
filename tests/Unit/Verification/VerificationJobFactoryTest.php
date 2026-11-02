<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Unit\Verification;

use PhpTaintTrace\Verification\Model\AuthorizationEvidence;
use PhpTaintTrace\Verification\Model\DetectorCandidate;
use PhpTaintTrace\Verification\Model\DetectorEvidence;
use PhpTaintTrace\Verification\Model\EnvironmentEvidence;
use PhpTaintTrace\Verification\Model\ReasonCode;
use PhpTaintTrace\Verification\Model\RequestEvidence;
use PhpTaintTrace\Verification\Model\SinkEvidence;
use PhpTaintTrace\Verification\Model\TaintEvidence;
use PhpTaintTrace\Verification\Verifier\VerificationJobFactory;
use PHPUnit\Framework\TestCase;

final class VerificationJobFactoryTest extends TestCase
{
    public function testFactoryMapsAllSupportedCategoriesToOracleTypes(): void
    {
        $factory = new VerificationJobFactory('local');

        $cases = array(
            array('rce', '/rce?cmd=id', 'rce_oracle', 'cmd'),
            array('ssrf', '/ssrf?url=http%3A%2F%2F127.0.0.1%2F', 'ssrf_oracle', 'url'),
            array('sqli', '/sqli?q=1', 'sqli_oracle', 'q'),
            array('file', '/file?path=%2Fetc%2Fhostname', 'file_oracle', 'path'),
            array('xss', '/xss?name=alice', 'xss_oracle', 'name'),
            array('idor', '/idor?resource_id=42&actor_id=1043&mode=vuln', 'idor_oracle', 'resource_id'),
            array('xxe', '/xxe?xml=%3Croot%3Ealice%3C%2Froot%3E', 'xxe_oracle', 'xml'),
        );

        foreach ($cases as $case) {
            [$category, $uri, $oracle, $target] = $case;
            $job = $factory->createFromCandidate($this->candidate($category, $uri));
            self::assertNotNull($job, sprintf('expected job for category %s', $category));
            self::assertSame($oracle, $job->oracleType());
            self::assertSame($category, $job->sinkCategory());
            self::assertSame($target, $job->replayPlan()['target_query_param'] ?? null);
        }
    }

    public function testFactoryPromotesXssCandidateToIdorOracleWhenRequestShapeMatches(): void
    {
        $factory = new VerificationJobFactory('remote_lab');
        $job = $factory->createFromCandidate(
            $this->candidate('xss', '/idor?resource_id=42&actor_id=1043&mode=vuln')
        );

        self::assertNotNull($job);
        self::assertSame('idor', $job->sinkCategory());
        self::assertSame('idor_oracle', $job->oracleType());
        self::assertSame('resource_id', $job->replayPlan()['idor_resource_param'] ?? null);
        self::assertSame('actor_id', $job->replayPlan()['idor_actor_param'] ?? null);
        self::assertSame('mode', $job->replayPlan()['idor_mode_param'] ?? null);
    }

    public function testFactorySkipsCandidatesWithoutFindings(): void
    {
        $candidate = new DetectorCandidate(
            id: 'candidate-no-findings',
            sinkName: 'system',
            sinkCategory: 'rce',
            reasonCodes: array(ReasonCode::DETECTOR_TAINT_INPUT),
            detectorEvidence: new DetectorEvidence(
                findingCount: 0,
                detectors: array(),
                severities: array(),
                messages: array()
            ),
            taintEvidence: new TaintEvidence(true, array(0), array('_GET')),
            sinkEvidence: new SinkEvidence('system', 'rce', 1, array(0 => 'primary')),
            requestEvidence: new RequestEvidence(gmdate('c'), 'cli-server', 'GET', '/rce?cmd=id'),
            environmentEvidence: new EnvironmentEvidence(PHP_VERSION, PHP_SAPI, get_loaded_extensions()),
            authorizationEvidence: new AuthorizationEvidence(null, null, null)
        );

        $job = (new VerificationJobFactory('local'))->createFromCandidate($candidate);
        self::assertNull($job);
    }

    public function testFactoryCarriesReplayTransportContextFromCandidateRequestMetadata(): void
    {
        $factory = new VerificationJobFactory('local');
        $job = $factory->createFromCandidate(
            $this->candidate(
                'ssrf',
                '/ssrf?url=http%3A%2F%2F127.0.0.1%2F',
                array(
                    'request_headers' => array(
                        'user-agent' => 'ptt-test-agent',
                        'accept' => 'text/html',
                    ),
                    'cookie_keys' => array('PHPSESSID', 'csrftoken'),
                )
            )
        );

        self::assertNotNull($job);
        self::assertSame(
            array(
                'accept' => 'text/html',
                'user-agent' => 'ptt-test-agent',
            ),
            $job->replayPlan()['replay_headers'] ?? null
        );
        self::assertSame(
            array(
                'PHPSESSID' => '1',
                'csrftoken' => '1',
            ),
            $job->replayPlan()['replay_cookies'] ?? null
        );
    }

    public function testFactoryBuildsPostBodyTargetPlanWhenBodyMetadataIsAvailable(): void
    {
        $factory = new VerificationJobFactory('local');
        $job = $factory->createFromCandidate(
            $this->candidate(
                'rce',
                '/rce',
                array(
                    'request_headers' => array(
                        'content-type' => 'application/x-www-form-urlencoded',
                    ),
                    'request_body' => 'cmd=id&keep=1',
                ),
                requestMethod: 'POST'
            )
        );

        self::assertNotNull($job);
        self::assertSame('POST', $job->replayPlan()['request_method'] ?? null);
        self::assertSame(array('POST'), $job->replayPlan()['allowed_methods'] ?? null);
        self::assertSame('body', $job->replayPlan()['target_param_location'] ?? null);
        self::assertSame('cmd', $job->replayPlan()['target_body_param'] ?? null);
        self::assertSame('cmd=id&keep=1', $job->replayPlan()['replay_body'] ?? null);
    }

    public function testFactoryBuildsJsonBodyTargetPlanWhenJsonMetadataIsAvailable(): void
    {
        $factory = new VerificationJobFactory('local');

        $cases = array(
            array(
                'category' => 'rce',
                'uri' => '/api/json/rce/system',
                'body' => '{"task":{"command":"id"},"metadata":{"source":"json-lab"}}',
                'target' => 'task.command',
            ),
            array(
                'category' => 'file',
                'uri' => '/api/json/file/lfi',
                'body' => '{"file":{"page":"home"},"options":{"suffix":".php"}}',
                'target' => 'file.page',
            ),
            array(
                'category' => 'sqli',
                'uri' => '/api/json/sqli/error',
                'body' => '{"lookup":{"id":"1"},"options":{"limit":"10"}}',
                'target' => 'lookup.id',
            ),
        );

        foreach ($cases as $case) {
            $job = $factory->createFromCandidate(
                $this->candidate(
                    $case['category'],
                    $case['uri'],
                    array(
                        'request_headers' => array(
                            'content-type' => 'application/json',
                        ),
                        'request_body' => $case['body'],
                        'request_body_format' => 'json',
                    ),
                    requestMethod: 'POST'
                )
            );

            self::assertNotNull($job, sprintf('expected JSON job for %s', $case['category']));
            self::assertSame('POST', $job->replayPlan()['request_method'] ?? null);
            self::assertSame('body', $job->replayPlan()['target_param_location'] ?? null);
            self::assertSame($case['target'], $job->replayPlan()['target_body_param'] ?? null);
            self::assertSame('json', $job->replayPlan()['target_body_format'] ?? null);
            self::assertSame($case['target'], $job->replayPlan()['target_json_path'] ?? null);
            self::assertSame('json', $job->replayPlan()['request_body_format'] ?? null);
            self::assertSame($case['body'], $job->replayPlan()['replay_body'] ?? null);
        }
    }

    public function testFactorySkipsRoutingQueryKeysWhenSelectingMutationTarget(): void
    {
        $factory = new VerificationJobFactory('local');
        $job = $factory->createFromCandidate(
            $this->candidate(
                'rce',
                '/?sink=eval&mode=vuln&code=echo%20xtanzi%3B',
                sinkName: 'include_or_eval'
            )
        );

        self::assertNotNull($job);
        self::assertSame('code', $job->replayPlan()['target_query_param'] ?? null);
    }

    /**
     * @param array<string, mixed> $requestMetadata
     */
    private function candidate(
        string $sinkCategory,
        string $requestUri,
        array $requestMetadata = array(),
        string $requestMethod = 'GET',
        ?string $sinkName = null
    ): DetectorCandidate {
        $resolvedSinkName = $sinkName ?? match ($sinkCategory) {
            'rce' => 'system',
            'ssrf' => 'file_get_contents',
            'sqli' => 'mysqli_query',
            'file' => 'file_get_contents',
            'xxe' => 'simplexml_load_string',
            default => 'printf',
        };

        return new DetectorCandidate(
            id: 'candidate-' . md5($sinkCategory . '|' . $requestUri),
            sinkName: $resolvedSinkName,
            sinkCategory: $sinkCategory,
            reasonCodes: array(ReasonCode::DETECTOR_TAINT_INPUT),
            detectorEvidence: new DetectorEvidence(
                findingCount: 1,
                detectors: array('taint-input-detector'),
                severities: array('debug'),
                messages: array('tainted input reached sink')
            ),
            taintEvidence: new TaintEvidence(true, array(0), array('_GET')),
            sinkEvidence: new SinkEvidence(
                sinkName: 'sink',
                sinkCategory: $sinkCategory,
                argumentCount: 1,
                argumentRoles: array(0 => 'primary')
            ),
            requestEvidence: new RequestEvidence(gmdate('c'), 'cli-server', $requestMethod, $requestUri, $requestMetadata),
            environmentEvidence: new EnvironmentEvidence(PHP_VERSION, PHP_SAPI, get_loaded_extensions()),
            authorizationEvidence: new AuthorizationEvidence(null, null, null)
        );
    }
}
