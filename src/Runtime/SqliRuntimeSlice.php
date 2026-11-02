<?php

declare(strict_types=1);

namespace PhpTaintTrace\Runtime;

use PhpTaintTrace\Core\TaintedValue;
use PhpTaintTrace\Detector\PayloadKeywordDetector;
use PhpTaintTrace\Detector\TaintInputDetector;
use PhpTaintTrace\Instrumentation\BaselineHookPlan;
use PhpTaintTrace\Instrumentation\HookDefinition;
use PhpTaintTrace\Instrumentation\HookHandlerRegistry;
use PhpTaintTrace\Instrumentation\InstrumentationBackendInterface;
use PhpTaintTrace\Instrumentation\InstrumentationBootstrapReport;
use PhpTaintTrace\Instrumentation\LegacyBaselineHookPlanFactory;
use PhpTaintTrace\Instrumentation\RequestTaintSeeder;
use PhpTaintTrace\Instrumentation\RuntimeInstrumentationBootstrap;
use PhpTaintTrace\Model\Finding;
use PhpTaintTrace\Model\SinkCategory;
use PhpTaintTrace\Verification\Detector\CandidateBuilder;
use PhpTaintTrace\Verification\Model\DetectorCandidate;
use PhpTaintTrace\Verification\Oracle\SqliReplayTelemetryStore;

final class SqliRuntimeSlice
{
    private readonly HookFindingStore $store;
    private readonly HookCandidateStore $candidateStore;
    private readonly HookDetectionRunner $runner;

    public function __construct(
        private readonly InstrumentationBackendInterface $backend,
        ?DetectorPipeline $pipeline = null,
        private readonly bool $emitCandidates = false
    ) {
        $this->store = new HookFindingStore();
        $this->candidateStore = new HookCandidateStore();
        $this->runner = new HookDetectionRunner(
            $pipeline ?? new DetectorPipeline(
                new TaintInputDetector(),
                new PayloadKeywordDetector('xtanzi')
            ),
            $this->store,
            $this->backend,
            $this->emitCandidates ? new CandidateBuilder() : null,
            $this->candidateStore
        );
    }

    public function bootstrap(): InstrumentationBootstrapReport
    {
        $plan = $this->sqliHookPlan();
        $handlers = new HookHandlerRegistry(true);
        foreach ($plan->hooks() as $hook) {
            $hookId = $hook->id();
            $sinkName = $hook->target();

            $handlers->register($hookId, function ($context) use ($hookId, $sinkName): void {
                $rawArguments = $context->arguments();
                $arguments = $this->extractSqlArguments($hookId, $rawArguments);
                $metadata = $this->extractSqlMetadata($hookId, $rawArguments);
                $this->captureReplaySqlTelemetry($hookId, $sinkName, $metadata);
                $this->runner->inspect($sinkName, SinkCategory::SQLI, $arguments, $metadata);
            });
        }

        $bootstrap = new RuntimeInstrumentationBootstrap($this->backend);
        return $bootstrap->bootstrap($plan, $handlers);
    }

    public function requestTaintSeeder(): RequestTaintSeeder
    {
        return new RequestTaintSeeder($this->backend);
    }

    /**
     * @return Finding[]
     */
    public function findings(): array
    {
        return $this->store->all();
    }

    public function clearFindings(): void
    {
        $this->store->clear();
    }

    /**
     * @return DetectorCandidate[]
     */
    public function candidates(): array
    {
        return $this->candidateStore->all();
    }

    public function clearCandidates(): void
    {
        $this->candidateStore->clear();
    }

    private function sqliHookPlan(): BaselineHookPlan
    {
        $hooks = array_filter(
            LegacyBaselineHookPlanFactory::create()->hooks(),
            static fn (HookDefinition $hook): bool => str_starts_with($hook->id(), 'sink.sqli.')
                || str_starts_with($hook->id(), 'method.sqli.')
        );

        return new BaselineHookPlan(...array_values($hooks));
    }

    /**
     * @param array<int, mixed> $arguments
     * @return array<int, mixed>
     */
    private function extractSqlArguments(string $hookId, array $arguments): array
    {
        if (str_starts_with($hookId, 'method.sqli.')) {
            return $this->takeArgument($arguments, 0);
        }

        return match ($hookId) {
            'sink.sqli.mysqli_init' => array(),
            'sink.sqli.mysqli_execute_query',
            'sink.sqli.mysqli_multi_query',
            'sink.sqli.mysqli_query',
            'sink.sqli.mysqli_prepare',
            'sink.sqli.mysqli_real_query',
            'sink.sqli.oci_parse',
            'sink.sqli.pg_query',
            'sink.sqli.pg_query_params',
            'sink.sqli.sqlsrv_prepare',
            'sink.sqli.sqlsrv_query',
            'sink.sqli.pg_send_query',
            'sink.sqli.pg_send_query_params' => $this->takeArgument($arguments, 1),
            'sink.sqli.pg_prepare',
            'sink.sqli.pg_query_prepared',
            'sink.sqli.pg_send_prepare',
            'sink.sqli.pg_execute',
            'sink.sqli.pg_send_execute' => $this->takeArgument($arguments, 2),
            'sink.sqli.oci_execute' => array(),
            default => $arguments,
        };
    }

    /**
     * @param array<int, mixed> $arguments
     * @return array<int, mixed>
     */
    private function takeArgument(array $arguments, int $index): array
    {
        if (!array_key_exists($index, $arguments)) {
            return array();
        }

        return array($arguments[$index]);
    }

    /**
     * @param array<int, mixed> $arguments
     * @return array<string, mixed>
     */
    private function extractSqlMetadata(string $hookId, array $arguments): array
    {
        $query = null;
        $statementName = null;
        $parameters = null;

        if (str_starts_with($hookId, 'method.sqli.')) {
            $query = $arguments[0] ?? null;
            if ($hookId === 'method.sqli.mysqli.execute_query') {
                $parameters = $arguments[1] ?? null;
            }
        } else {
            switch ($hookId) {
                case 'sink.sqli.mysqli_execute_query':
                    $query = $arguments[1] ?? null;
                    $parameters = $arguments[2] ?? null;
                    break;
                case 'sink.sqli.mysqli_multi_query':
                case 'sink.sqli.mysqli_query':
                case 'sink.sqli.mysqli_prepare':
                case 'sink.sqli.mysqli_real_query':
                case 'sink.sqli.oci_parse':
                case 'sink.sqli.pg_query':
                case 'sink.sqli.pg_send_query':
                case 'sink.sqli.sqlsrv_prepare':
                    $query = $arguments[1] ?? null;
                    break;
                case 'sink.sqli.sqlsrv_query':
                    $query = $arguments[1] ?? null;
                    $parameters = $arguments[2] ?? null;
                    break;
                case 'sink.sqli.pg_query_params':
                case 'sink.sqli.pg_send_query_params':
                    $query = $arguments[1] ?? null;
                    $parameters = $arguments[2] ?? null;
                    break;
                case 'sink.sqli.pg_prepare':
                case 'sink.sqli.pg_send_prepare':
                    $statementName = $arguments[1] ?? null;
                    $query = $arguments[2] ?? null;
                    break;
                case 'sink.sqli.pg_query_prepared':
                case 'sink.sqli.pg_execute':
                case 'sink.sqli.pg_send_execute':
                    $statementName = $arguments[1] ?? null;
                    $parameters = $arguments[2] ?? null;
                    break;
                default:
                    break;
            }
        }

        $normalizedQuery = $this->normalizeSqlString($query);
        $normalizedStatementName = $this->normalizeSqlString($statementName);
        $normalizedParameters = $this->normalizeSqlValue($parameters);

        $sql = array(
            'hook_id' => $hookId,
        );
        if ($normalizedQuery !== null) {
            $sql['query'] = $normalizedQuery;
        }
        if ($normalizedStatementName !== null) {
            $sql['statement_name'] = $normalizedStatementName;
        }
        if ($normalizedParameters !== null) {
            $sql['parameters'] = $normalizedParameters;
        }

        if (count($sql) === 1) {
            return array();
        }

        return array('sql' => $sql);
    }

    private function normalizeSqlString(mixed $value): ?string
    {
        $normalized = $this->normalizeSqlValue($value);
        if (!is_string($normalized)) {
            return null;
        }

        return trim($normalized) === '' ? null : $normalized;
    }

    private function normalizeSqlValue(mixed $value, int $depth = 0): mixed
    {
        if ($depth >= 8) {
            return '[depth_limit]';
        }

        if ($value instanceof TaintedValue) {
            return $this->normalizeSqlValue($value->value(), $depth + 1);
        }

        if ($value === null || is_scalar($value)) {
            return $value;
        }

        if (is_array($value)) {
            $normalized = array();
            foreach ($value as $key => $entry) {
                $normalized[$key] = $this->normalizeSqlValue($entry, $depth + 1);
            }

            return $normalized;
        }

        if ($value instanceof \Stringable) {
            return (string) $value;
        }

        if (is_object($value)) {
            return sprintf('[object:%s]', $value::class);
        }

        if (is_resource($value)) {
            return sprintf('[resource:%s]', get_resource_type($value));
        }

        return sprintf('[type:%s]', gettype($value));
    }

    /**
     * @param array<string, mixed> $metadata
     */
    private function captureReplaySqlTelemetry(string $hookId, string $sinkName, array $metadata): void
    {
        if (!$this->isReplayRequest()) {
            return;
        }

        $replayId = $this->replayIdFromServer();
        if ($replayId === null) {
            return;
        }

        $sql = is_array($metadata['sql'] ?? null) ? $metadata['sql'] : array();
        if ($sql === array()) {
            return;
        }

        SqliReplayTelemetryStore::append($replayId, array(
            'captured_at' => gmdate('c'),
            'request_method' => is_scalar($_SERVER['REQUEST_METHOD'] ?? null)
                ? (string) $_SERVER['REQUEST_METHOD']
                : null,
            'request_uri' => is_scalar($_SERVER['REQUEST_URI'] ?? null)
                ? (string) $_SERVER['REQUEST_URI']
                : null,
            'payload_label' => is_scalar($_SERVER['HTTP_X_PHP_TAINT_TRACE_REPLAY_LABEL'] ?? null)
                ? (string) $_SERVER['HTTP_X_PHP_TAINT_TRACE_REPLAY_LABEL']
                : null,
            'mutated_parameter' => is_scalar($_SERVER['HTTP_X_PHP_TAINT_TRACE_REPLAY_MUTATED_PARAMETER'] ?? null)
                ? (string) $_SERVER['HTTP_X_PHP_TAINT_TRACE_REPLAY_MUTATED_PARAMETER']
                : null,
            'mutated_location' => is_scalar($_SERVER['HTTP_X_PHP_TAINT_TRACE_REPLAY_MUTATED_LOCATION'] ?? null)
                ? (string) $_SERVER['HTTP_X_PHP_TAINT_TRACE_REPLAY_MUTATED_LOCATION']
                : null,
            'hook_id' => $hookId,
            'sink_name' => $sinkName,
            'sql' => $sql,
        ));
    }

    private function isReplayRequest(): bool
    {
        $raw = $_SERVER['HTTP_X_PHP_TAINT_TRACE_REPLAY'] ?? null;
        if (!is_scalar($raw)) {
            return false;
        }

        $normalized = strtolower(trim((string) $raw));
        return in_array($normalized, array('1', 'true', 'yes'), true);
    }

    private function replayIdFromServer(): ?string
    {
        $raw = $_SERVER['HTTP_X_PHP_TAINT_TRACE_REPLAY_ID'] ?? null;
        if (!is_scalar($raw)) {
            return null;
        }

        $replayId = trim((string) $raw);
        if ($replayId === '' || !SqliReplayTelemetryStore::isValidReplayId($replayId)) {
            return null;
        }

        return $replayId;
    }
}
