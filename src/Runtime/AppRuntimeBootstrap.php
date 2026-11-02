<?php

declare(strict_types=1);

namespace PhpTaintTrace\Runtime;

use PhpTaintTrace\Instrumentation\Backend\NoopInstrumentationBackend;
use PhpTaintTrace\Instrumentation\Backend\XmarkExtensionBackend;
use PhpTaintTrace\Instrumentation\InstrumentationBackendInterface;
use PhpTaintTrace\Model\Finding;
use PhpTaintTrace\Reporting\RuntimeReportWriterFactory;
use PhpTaintTrace\Reporting\RuntimeReportWriterInterface;
use PhpTaintTrace\Verification\Verifier\JsonlVerificationQueue;
use PhpTaintTrace\Verification\Verifier\VerificationJobFactory;
use PhpTaintTrace\Verification\Model\DetectorCandidate;

final class AppRuntimeBootstrap
{
    private bool $shutdownRegistered = false;
    private ?RuntimeReportWriterInterface $reportWriter = null;

    public function __construct(
        private readonly BaselineRuntime $runtime,
        private readonly AppRuntimeConfig $config
    ) {
    }

    public static function createFromEnvironment(
        ?InstrumentationBackendInterface $backend = null,
        ?AppRuntimeConfig $config = null
    ): self {
        $resolvedConfig = $config ?? AppRuntimeConfig::fromEnvironment();
        $resolvedBackend = $backend ?? self::autoDetectBackend();

        return new self(
            new BaselineRuntime(
                $resolvedBackend,
                $resolvedConfig->enableOpcodeHooks(),
                $resolvedConfig->opcodeHookProfile(),
                $resolvedConfig->emitCandidates() || $resolvedConfig->enableVerifier()
            ),
            $resolvedConfig
        );
    }

    public function config(): AppRuntimeConfig
    {
        return $this->config;
    }

    public function runtime(): BaselineRuntime
    {
        return $this->runtime;
    }

    public function bootstrapCurrentRequest(): BaselineRuntimeRequestReport
    {
        return $this->runtime->startRequest(
            $_GET,
            $_POST,
            $_COOKIE,
            $_FILES,
            $_REQUEST,
            $_SERVER
        );
    }

    /**
     * @param array<string, mixed> $get
     * @param array<string, mixed> $post
     * @param array<string, mixed> $cookie
     * @param array<string, mixed> $files
     * @param array<string, mixed> $request
     * @param array<string, mixed> $server
     */
    public function bootstrapRequest(
        array &$get,
        array &$post,
        array &$cookie,
        array &$files,
        array &$request,
        array &$server
    ): BaselineRuntimeRequestReport {
        return $this->runtime->startRequest(
            $get,
            $post,
            $cookie,
            $files,
            $request,
            $server
        );
    }

    public function registerShutdownHandler(): void
    {
        if ($this->shutdownRegistered) {
            return;
        }

        register_shutdown_function(function (): void {
            $this->flushFindings();
        });
        $this->shutdownRegistered = true;
    }

    public function flushFindings(): int
    {
        $findings = $this->runtime->findings();
        $count = count($findings);
        if ($count === 0) {
            return 0;
        }

        $payload = array(
            'timestamp' => gmdate('c'),
            'sapi' => PHP_SAPI,
            'request_method' => $_SERVER['REQUEST_METHOD'] ?? null,
            'request_uri' => $_SERVER['REQUEST_URI'] ?? null,
            'findings' => array_map(
                static fn (Finding $finding): array => self::serializeFinding($finding),
                $findings
            ),
        );
        if ($this->config->emitCandidates()) {
            $payload['candidates'] = array_map(
                static fn (DetectorCandidate $candidate): array => self::serializeCandidate($candidate),
                $this->runtime->candidates()
            );
        }

        if ($this->config->enableVerifier() && !self::isVerifierReplayRequest()) {
            $this->enqueueVerificationJobs($this->runtime->candidates());
        }

        $json = json_encode($payload, JSON_UNESCAPED_SLASHES);
        if (is_string($json)) {
            try {
                $this->reportWriter()->write($payload);
            } catch (\Throwable $error) {
                error_log('[php_taint_trace] report writer failure: ' . $error->getMessage());
            }
        }

        if ($this->config->clearFindingsAfterFlush()) {
            $this->runtime->clearFindings();
            $this->runtime->clearCandidates();
        }

        return $count;
    }

    private function reportWriter(): RuntimeReportWriterInterface
    {
        if ($this->reportWriter instanceof RuntimeReportWriterInterface) {
            return $this->reportWriter;
        }

        $this->reportWriter = RuntimeReportWriterFactory::fromConfig($this->config);
        return $this->reportWriter;
    }

    /**
     * @return array<string, mixed>
     */
    private static function serializeFinding(Finding $finding): array
    {
        return array(
            'detector' => $finding->detector(),
            'severity' => $finding->severity(),
            'message' => $finding->message(),
            'sink_name' => $finding->sinkName(),
            'sink_category' => $finding->sinkCategory()->value,
            'metadata' => $finding->metadata(),
        );
    }

    /**
     * @return array<string, mixed>
     */
    private static function serializeCandidate(DetectorCandidate $candidate): array
    {
        return $candidate->toArray();
    }

    private static function isVerifierReplayRequest(): bool
    {
        $raw = $_SERVER['HTTP_X_PHP_TAINT_TRACE_REPLAY'] ?? null;
        if (!is_scalar($raw)) {
            return false;
        }

        $normalized = strtolower(trim((string) $raw));
        return in_array($normalized, array('1', 'true', 'yes'), true);
    }

    /**
     * @param DetectorCandidate[] $candidates
     */
    private function enqueueVerificationJobs(array $candidates): void
    {
        try {
            $queue = new JsonlVerificationQueue($this->config->verifierRuntimeDir());
            $factory = new VerificationJobFactory($this->config->verifierReplayTarget());
            $jobs = array();
            $dedup = array();

            foreach ($candidates as $candidate) {
                $job = $factory->createFromCandidate($candidate);
                if ($job === null) {
                    continue;
                }

                $dedupKey = $job->dedupKey();
                if (isset($dedup[$dedupKey])) {
                    continue;
                }

                $dedup[$dedupKey] = true;
                $jobs[] = $job;
            }

            if ($jobs !== array()) {
                $queue->enqueueMany($jobs);
            }
        } catch (\Throwable $error) {
            error_log('[php_taint_trace] verifier enqueue failure: ' . $error->getMessage());
        }
    }

    private static function autoDetectBackend(): InstrumentationBackendInterface
    {
        if (
            function_exists('xmark') &&
            function_exists('xcheck') &&
            (function_exists('xmark_register_hook') || function_exists('xregister_opcode_callback'))
        ) {
            return new XmarkExtensionBackend();
        }

        return new NoopInstrumentationBackend();
    }
}
