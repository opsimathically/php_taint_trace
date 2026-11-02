<?php

declare(strict_types=1);

$rootDir = dirname(__DIR__);
$autoloadPath = $rootDir . '/vendor/autoload.php';
if (!is_file($autoloadPath)) {
    fwrite(STDERR, "[php_taint_trace] Missing Composer autoload at {$autoloadPath}" . PHP_EOL);
    exit(1);
}

require $autoloadPath;

use PhpTaintTrace\Verification\Oracle\FileOracle;
use PhpTaintTrace\Verification\Oracle\IdorOracle;
use PhpTaintTrace\Verification\Oracle\RceOracle;
use PhpTaintTrace\Verification\Oracle\SqliOracle;
use PhpTaintTrace\Verification\Oracle\SsrfOracle;
use PhpTaintTrace\Verification\Oracle\BrowserAwareXssOracle;
use PhpTaintTrace\Verification\Oracle\XssOracle;
use PhpTaintTrace\Verification\Oracle\XxeOracle;
use PhpTaintTrace\Verification\Storage\JsonlDecisionStore;
use PhpTaintTrace\Verification\Verifier\JsonlVerificationQueue;
use PhpTaintTrace\Verification\Verifier\VerifierRuntimeConfig;
use PhpTaintTrace\Verification\Verifier\VerificationWorker;

/**
 * @return array{drain: bool, max_cycles: int}
 */
function parseCliOptions(array $argv): array
{
    $drain = false;
    $maxCycles = 12;

    foreach ($argv as $index => $arg) {
        if ($index === 0) {
            continue;
        }

        if ($arg === '--drain') {
            $drain = true;
            continue;
        }

        if (str_starts_with($arg, '--max-cycles=')) {
            $value = substr($arg, strlen('--max-cycles='));
            if (preg_match('/^\d+$/', $value) === 1) {
                $maxCycles = max(1, (int) $value);
            }
            continue;
        }
    }

    return array(
        'drain' => $drain,
        'max_cycles' => $maxCycles,
    );
}

try {
    $rawArgv = $_SERVER['argv'] ?? ($GLOBALS['argv'] ?? array());
    $options = parseCliOptions(is_array($rawArgv) ? $rawArgv : array());
    $config = VerifierRuntimeConfig::fromEnvironment();
    $queue = new JsonlVerificationQueue($config->runtimeDir(), $config->claimTtlSeconds());
    $xssOracle = new XssOracle();
    if ($config->xssBrowserEnabled()) {
        $xssOracle = new BrowserAwareXssOracle(
            fallbackOracle: $xssOracle,
            browserProbeRunner: $config->xssBrowserProbeRunner(),
            enforceBrowserExecution: $config->xssBrowserEnforce(),
            probeTimeoutMs: $config->xssBrowserTimeoutMs()
        );
    }

    $worker = new VerificationWorker(
        $queue,
        $config->replayRunner(),
        array(
            new RceOracle(),
            new SsrfOracle(),
            new SqliOracle(),
            new FileOracle(),
            $xssOracle,
            new IdorOracle(),
            new XxeOracle(),
        ),
        maxAttempts: $config->maxAttempts(),
        artifactDirectory: $queue->artifactsDirectory(),
        verificationRounds: $config->verificationRounds(),
        decisionStore: new JsonlDecisionStore($config->runtimeDir())
    );

    $processed = 0;
    $cycles = 0;
    $batchSize = max(1, $config->batchSize());
    do {
        $cycles++;
        $processedThisCycle = $worker->process($batchSize);
        $processed += $processedThisCycle;

        if (!$options['drain']) {
            break;
        }

        if ($processedThisCycle <= 0) {
            break;
        }

        if ($queue->pendingCount() <= 0) {
            break;
        }
    } while ($cycles < $options['max_cycles']);

    $queueHealth = $queue->queueHealth();
    $pending = (int) ($queueHealth['pending_count'] ?? 0);
    $activeClaims = (int) ($queueHealth['active_claim_count'] ?? 0);
    $staleClaims = (int) ($queueHealth['stale_claim_count'] ?? 0);
    $deadLetters = (int) ($queueHealth['dead_letter_count'] ?? 0);

    fwrite(
        STDOUT,
        sprintf(
            "[php_taint_trace] verifier worker processed=%d pending=%d dead_letters=%d active_claims=%d stale_claims=%d runtime_dir=%s%s",
            $processed,
            $pending,
            $deadLetters,
            $activeClaims,
            $staleClaims,
            $config->runtimeDir(),
            $options['drain'] ? sprintf(' drain_cycles=%d', $cycles) : '',
            PHP_EOL
        )
    );
    exit(0);
} catch (Throwable $error) {
    fwrite(STDERR, '[php_taint_trace] verifier worker failure: ' . $error->getMessage() . PHP_EOL);
    exit(1);
}
