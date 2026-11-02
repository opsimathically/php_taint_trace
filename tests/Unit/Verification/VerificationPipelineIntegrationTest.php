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
use PhpTaintTrace\Verification\Oracle\FileOracle;
use PhpTaintTrace\Verification\Oracle\IdorOracle;
use PhpTaintTrace\Verification\Oracle\RceOracle;
use PhpTaintTrace\Verification\Oracle\SqliOracle;
use PhpTaintTrace\Verification\Oracle\SsrfOracle;
use PhpTaintTrace\Verification\Oracle\XssOracle;
use PhpTaintTrace\Verification\Oracle\XxeOracle;
use PhpTaintTrace\Verification\Storage\JsonlDecisionStore;
use PhpTaintTrace\Verification\Verifier\JsonlVerificationQueue;
use PhpTaintTrace\Verification\Verifier\LocalReplayRunner;
use PhpTaintTrace\Verification\Verifier\VerificationJobFactory;
use PhpTaintTrace\Verification\Verifier\VerificationWorker;
use PHPUnit\Framework\TestCase;

final class VerificationPipelineIntegrationTest extends TestCase
{
    /**
     * @var array<int, resource>
     */
    private array $serverProcesses = array();

    /**
     * @var string[]
     */
    private array $serverDocRoots = array();

    protected function tearDown(): void
    {
        parent::tearDown();

        foreach ($this->serverProcesses as $process) {
            if (!is_resource($process)) {
                continue;
            }

            @proc_terminate($process);
            @proc_close($process);
        }
        $this->serverProcesses = array();

        foreach ($this->serverDocRoots as $docRoot) {
            if (!is_dir($docRoot)) {
                continue;
            }

            $this->deleteDir($docRoot);
        }
        $this->serverDocRoots = array();
    }

    public function testCandidateToQueueToWorkerPipelineConfirmsAllPhaseDClasses(): void
    {
        $callbackPort = $this->startCallbackServer();
        $mainPort = $this->startMainFixtureServer();
        $runtimeDir = sys_get_temp_dir() . '/php-taint-trace-verifier-pipeline-' . uniqid('', true);
        $queue = new JsonlVerificationQueue($runtimeDir);
        $factory = new VerificationJobFactory('local');

        $rceCandidate = $this->candidate(
            'candidate-rce',
            'system',
            'rce',
            '/rce?cmd=echo%20xtanzi'
        );
        $ssrfCandidate = $this->candidate(
            'candidate-ssrf',
            'file_get_contents',
            'ssrf',
            '/ssrf?url=' . rawurlencode(sprintf('http://127.0.0.1:%d/?name=xtanzi', $callbackPort))
        );
        $sqliCandidate = $this->candidate(
            'candidate-sqli',
            'mysqli_query',
            'sqli',
            '/sqli?q=1'
        );
        $fileCandidate = $this->candidate(
            'candidate-file',
            'file_get_contents',
            'file',
            '/file?path=' . rawurlencode('/etc/hostname')
        );
        $xssCandidate = $this->candidate(
            'candidate-xss',
            'printf',
            'xss',
            '/xss?name=' . rawurlencode('<script>phase-d</script>')
        );
        $idorCandidate = $this->candidate(
            'candidate-idor',
            'printf',
            'xss',
            '/idor?resource_id=42&actor_id=1043&mode=vuln'
        );
        $xxeCandidate = $this->candidate(
            'candidate-xxe',
            'simplexml_load_string',
            'xxe',
            '/xxe?xml=%3C!DOCTYPE%20root%20%5B%3C!ENTITY%20xxe%20SYSTEM%20%22http%3A%2F%2F127.0.0.1%3A' . $callbackPort . '%2F%3Fname%3Dxtanzi%22%3E%5D%3E%3Croot%3E%26xxe%3B%3C%2Froot%3E'
        );

        $rceJob = $factory->createFromCandidate($rceCandidate);
        $ssrfJob = $factory->createFromCandidate($ssrfCandidate);
        $sqliJob = $factory->createFromCandidate($sqliCandidate);
        $fileJob = $factory->createFromCandidate($fileCandidate);
        $xssJob = $factory->createFromCandidate($xssCandidate);
        $idorJob = $factory->createFromCandidate($idorCandidate);
        $xxeJob = $factory->createFromCandidate($xxeCandidate);
        self::assertNotNull($rceJob);
        self::assertNotNull($ssrfJob);
        self::assertNotNull($sqliJob);
        self::assertNotNull($fileJob);
        self::assertNotNull($xssJob);
        self::assertNotNull($idorJob);
        self::assertNotNull($xxeJob);

        self::assertTrue($queue->enqueue($rceJob));
        self::assertTrue($queue->enqueue($ssrfJob));
        self::assertTrue($queue->enqueue($sqliJob));
        self::assertTrue($queue->enqueue($fileJob));
        self::assertTrue($queue->enqueue($xssJob));
        self::assertTrue($queue->enqueue($idorJob));
        self::assertTrue($queue->enqueue($xxeJob));

        $worker = new VerificationWorker(
            $queue,
            new LocalReplayRunner(
                sprintf('http://127.0.0.1:%d', $mainPort),
                callbackBaseOverride: sprintf('http://127.0.0.1:%d', $callbackPort)
            ),
            array(
                new RceOracle(),
                new SsrfOracle(),
                new SqliOracle(),
                new FileOracle(),
                new XssOracle(),
                new IdorOracle(),
                new XxeOracle(),
            ),
            maxAttempts: 2,
            artifactDirectory: $queue->artifactsDirectory(),
            decisionStore: new JsonlDecisionStore($runtimeDir)
        );

        self::assertSame(7, $worker->process(20));

        $lines = file($queue->resultsPath(), FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        self::assertIsArray($lines);
        self::assertCount(7, $lines);

        $confirmed = array();
        foreach ($lines as $line) {
            $payload = json_decode($line, true, 512, JSON_THROW_ON_ERROR);
            self::assertSame('confirmed', $payload['outcome']);
            $confirmed[] = $payload['metadata']['sink_category'] ?? null;
        }

        sort($confirmed);
        self::assertSame(array('file', 'idor', 'rce', 'sqli', 'ssrf', 'xss', 'xxe'), $confirmed);

        $decisionRows = file($runtimeDir . '/decisions.jsonl', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        self::assertIsArray($decisionRows);
        self::assertCount(7, $decisionRows);

        $tiers = array();
        foreach ($decisionRows as $decisionRow) {
            $decisionPayload = json_decode($decisionRow, true, 512, JSON_THROW_ON_ERROR);
            $tiers[] = $decisionPayload['decision_tier'] ?? null;
            self::assertArrayHasKey('score_breakdown', $decisionPayload);
            self::assertSame('phase_c_v1_step27', $decisionPayload['score_breakdown']['formula_version'] ?? null);
            self::assertIsArray($decisionPayload['reason_codes'] ?? null);
        }

        sort($tiers);
        self::assertSame(array('confirmed', 'confirmed', 'confirmed', 'confirmed', 'confirmed', 'confirmed', 'confirmed'), $tiers);
    }

    private function startMainFixtureServer(): int
    {
        $docRoot = sys_get_temp_dir() . '/php-taint-trace-verifier-main-' . uniqid('', true);
        mkdir($docRoot, 0775, true);
        $this->serverDocRoots[] = $docRoot;

file_put_contents($docRoot . '/index.php', <<<'PHP'
<?php

declare(strict_types=1);

function ptt_extract_xxe_entity_url(string $xml): ?string
{
    if (preg_match('/<!ENTITY\s+[a-zA-Z0-9_:-]+\s+SYSTEM\s+["\']([^"\']+)["\']\s*>/i', $xml, $matches) !== 1) {
        return null;
    }

    return trim((string) ($matches[1] ?? ''));
}

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
if ($path === '/rce') {
    $cmd = (string) ($_GET['cmd'] ?? 'echo safe');
    system($cmd);
    return;
}

if ($path === '/ssrf') {
    $url = (string) ($_GET['url'] ?? 'http://127.0.0.1:9/');
    $body = @file_get_contents($url);
    if ($body === false) {
        http_response_code(502);
        echo 'fetch failed';
        return;
    }

    echo $body;
    return;
}

if ($path === '/sqli') {
    $query = (string) ($_GET['q'] ?? '1');
    if (preg_match("/UNION\\s+SELECT\\s+'([^']+)'/i", $query, $matches) === 1) {
        echo $matches[1];
        return;
    }

    if ($query === '1') {
        echo 'alice';
        return;
    }

    echo 'no rows';
    return;
}

if ($path === '/file') {
    $requestedPath = (string) ($_GET['path'] ?? '/etc/hostname');
    if ($requestedPath === '/etc/hostname') {
        echo "fixture-host\n";
        return;
    }

    http_response_code(500);
    echo 'read failed';
    return;
}

if ($path === '/xss') {
    $name = (string) ($_GET['name'] ?? 'guest');
    printf('Hello %s', $name);
    return;
}

if ($path === '/idor') {
    $resourceId = (string) ($_GET['resource_id'] ?? '42');
    $actorId = (string) ($_GET['actor_id'] ?? '1043');
    $mode = (string) ($_GET['mode'] ?? 'vuln');
    $owner = (string) ((int) $resourceId + 1000);

    if ($mode === 'safe' && $actorId !== $owner) {
        http_response_code(403);
        echo 'forbidden';
        return;
    }

    printf('resource:%s owner:%s actor:%s mode:%s', $resourceId, $owner, $actorId, $mode);
    return;
}

if ($path === '/xxe') {
    $xml = (string) ($_GET['xml'] ?? '<root>safe</root>');
    $entityUrl = ptt_extract_xxe_entity_url($xml);
    if (is_string($entityUrl) && $entityUrl !== '') {
        $body = @file_get_contents($entityUrl);
        if (is_string($body) && $body !== '') {
            echo trim($body);
            return;
        }

        http_response_code(502);
        echo 'xml fetch failed';
        return;
    }

    $parsed = @simplexml_load_string($xml);
    if ($parsed === false) {
        http_response_code(400);
        echo 'xml parse failed';
        return;
    }

    echo trim((string) $parsed);
    return;
}

echo 'ok';
PHP
        );

        return $this->startServerProcess($docRoot, 'main fixture');
    }

    private function startCallbackServer(): int
    {
        $docRoot = sys_get_temp_dir() . '/php-taint-trace-verifier-callback-' . uniqid('', true);
        mkdir($docRoot, 0775, true);
        $this->serverDocRoots[] = $docRoot;

        file_put_contents($docRoot . '/index.php', <<<'PHP'
<?php

declare(strict_types=1);

$name = (string) ($_GET['name'] ?? 'guest');
printf('Hello %s', $name);
PHP
        );

        return $this->startServerProcess($docRoot, 'callback fixture');
    }

    private function startServerProcess(string $docRoot, string $label): int
    {
        $port = $this->allocateEphemeralPort();
        $descriptors = array(
            0 => array('file', '/dev/null', 'r'),
            1 => array('file', '/dev/null', 'w'),
            2 => array('file', '/dev/null', 'w'),
        );
        $command = sprintf('php -S 127.0.0.1:%d -t %s', $port, escapeshellarg($docRoot));
        $process = proc_open($command, $descriptors, $pipes, $docRoot);
        self::assertTrue(is_resource($process), sprintf('%s server process failed to start', $label));
        $this->serverProcesses[] = $process;

        $ready = false;
        for ($i = 0; $i < 100; $i++) {
            $socket = @fsockopen('127.0.0.1', $port, $errno, $errstr, 0.05);
            if (is_resource($socket)) {
                fclose($socket);
                $ready = true;
                break;
            }

            usleep(100000);
        }

        self::assertTrue($ready, sprintf('%s server did not start in time', $label));

        return $port;
    }

    private function allocateEphemeralPort(): int
    {
        $server = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
        self::assertNotFalse($server);
        $name = stream_socket_get_name($server, false);
        fclose($server);

        self::assertIsString($name);
        $segments = explode(':', $name);
        return (int) end($segments);
    }

    private function candidate(string $id, string $sinkName, string $sinkCategory, string $requestUri): DetectorCandidate
    {
        return new DetectorCandidate(
            id: $id,
            sinkName: $sinkName,
            sinkCategory: $sinkCategory,
            reasonCodes: array(
                ReasonCode::DETECTOR_TAINT_INPUT,
                $this->categoryReasonCode($sinkCategory),
            ),
            detectorEvidence: new DetectorEvidence(
                findingCount: 1,
                detectors: array('taint-input-detector'),
                severities: array('debug'),
                messages: array('Tainted input reached sink.')
            ),
            taintEvidence: new TaintEvidence(true, array(0), array('_GET')),
            sinkEvidence: new SinkEvidence(
                sinkName: $sinkName,
                sinkCategory: $sinkCategory,
                argumentCount: 1,
                argumentRoles: array(0 => 'primary')
            ),
            requestEvidence: new RequestEvidence(gmdate('c'), 'cli-server', 'GET', $requestUri),
            environmentEvidence: new EnvironmentEvidence(PHP_VERSION, PHP_SAPI, get_loaded_extensions()),
            authorizationEvidence: new AuthorizationEvidence(null, null, null)
        );
    }

    private function categoryReasonCode(string $sinkCategory): ReasonCode
    {
        return match ($sinkCategory) {
            'rce' => ReasonCode::CATEGORY_RCE,
            'ssrf' => ReasonCode::CATEGORY_SSRF,
            'sqli' => ReasonCode::CATEGORY_SQLI,
            'file' => ReasonCode::CATEGORY_FILE,
            'xss' => ReasonCode::CATEGORY_XSS,
            'idor' => ReasonCode::CATEGORY_IDOR,
            'xxe' => ReasonCode::CATEGORY_XXE,
            default => ReasonCode::DETECTOR_TAINT_INPUT,
        };
    }

    private function deleteDir(string $path): void
    {
        $items = scandir($path);
        if (!is_array($items)) {
            return;
        }

        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }

            $child = $path . '/' . $item;
            if (is_dir($child)) {
                $this->deleteDir($child);
                continue;
            }

            @unlink($child);
        }

        @rmdir($path);
    }
}
