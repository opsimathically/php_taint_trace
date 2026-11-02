<?php

declare(strict_types=1);

namespace PhpTaintTrace\Runtime;

use PhpTaintTrace\Core\TaintedValue;
use PhpTaintTrace\Instrumentation\InstrumentationBackendInterface;
use PhpTaintTrace\Model\Finding;
use PhpTaintTrace\Model\SinkCategory;
use PhpTaintTrace\Model\SinkInvocation;
use PhpTaintTrace\Verification\Detector\CandidateBuilder;

final class HookDetectionRunner
{
    public function __construct(
        private readonly DetectorPipeline $pipeline,
        private readonly HookFindingStore $store,
        private readonly ?InstrumentationBackendInterface $backend = null,
        private readonly ?CandidateBuilder $candidateBuilder = null,
        private readonly ?HookCandidateStore $candidateStore = null
    ) {
    }

    /**
     * @param array<int, mixed> $arguments
     * @param array<string, mixed> $metadata
     * @return Finding[]
     */
    public function inspect(string $sinkName, SinkCategory $category, array $arguments, array $metadata = array()): array
    {
        $invocationMetadata = $this->buildInvocationMetadata($metadata);
        $invocation = new SinkInvocation(
            $sinkName,
            $category,
            $this->normalizeArguments($arguments),
            $invocationMetadata
        );
        $findings = $this->pipeline->detect($invocation);
        $this->store->appendMany($findings);
        if ($this->candidateBuilder !== null && $this->candidateStore !== null) {
            $this->candidateStore->append($this->candidateBuilder->build($invocation, $findings));
        }

        return $findings;
    }

    /**
     * @param array<int, mixed> $arguments
     * @return array<int, mixed>
     */
    private function normalizeArguments(array $arguments): array
    {
        if ($this->backend === null) {
            return $arguments;
        }

        $normalized = array();
        foreach ($arguments as $argument) {
            if ($argument instanceof TaintedValue) {
                $normalized[] = $argument;
                continue;
            }

            if ($this->backend->isTainted($argument, true)) {
                $normalized[] = TaintedValue::tainted($argument, 'backend.runtime');
                continue;
            }

            $normalized[] = $argument;
        }

        return $normalized;
    }

    /**
     * @param array<string, mixed> $metadata
     * @return array<string, mixed>
     */
    private function buildInvocationMetadata(array $metadata): array
    {
        $stacktrace = $this->captureSinkStacktrace();
        if ($stacktrace !== array()) {
            $metadata['stacktrace'] = $stacktrace;
            $metadata['stacktrace_captured_at'] = gmdate('c');
        }

        return $metadata;
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    private function captureSinkStacktrace(): array
    {
        if (!function_exists('debug_backtrace')) {
            return array();
        }

        $frames = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 64);
        $captured = array();
        $level = 0;
        foreach ($frames as $frame) {
            if (!is_array($frame)) {
                continue;
            }

            if ($this->isInternalFrame($frame)) {
                continue;
            }

            $file = isset($frame['file']) && is_string($frame['file'])
                ? trim($frame['file'])
                : '';

            $where = $this->frameWhere($frame);
            $line = isset($frame['line']) && is_int($frame['line'])
                ? $frame['line']
                : null;
            $type = isset($frame['type']) && is_string($frame['type'])
                ? $frame['type']
                : null;

            $normalized = array('level' => $level);
            if ($where !== null) {
                $normalized['where'] = $where;
            }
            if ($file !== '') {
                $normalized['file_uri'] = $file;
            }
            if (is_int($line) && $line > 0) {
                $normalized['lineno'] = $line;
            }
            if ($type !== null && $type !== '') {
                $normalized['type'] = $type;
            }

            if (count($normalized) > 1) {
                $captured[] = $normalized;
                $level++;
            }

            if ($level >= 24) {
                break;
            }
        }

        return $captured;
    }

    /**
     * @param array<string, mixed> $frame
     */
    private function isInternalFrame(array $frame): bool
    {
        $class = isset($frame['class']) && is_string($frame['class'])
            ? trim($frame['class'])
            : '';
        if ($class !== '' && str_starts_with($class, 'PhpTaintTrace\\')) {
            return true;
        }

        $file = isset($frame['file']) && is_string($frame['file'])
            ? trim($frame['file'])
            : '';
        if ($file === '') {
            return false;
        }

        return str_contains($file, '/php_taint_trace/src/')
            || str_ends_with($file, '/src/Runtime/HookDetectionRunner.php');
    }

    /**
     * @param array<string, mixed> $frame
     */
    private function frameWhere(array $frame): ?string
    {
        $function = isset($frame['function']) && is_string($frame['function'])
            ? trim($frame['function'])
            : '';
        $class = isset($frame['class']) && is_string($frame['class'])
            ? trim($frame['class'])
            : '';
        $type = isset($frame['type']) && is_string($frame['type'])
            ? trim($frame['type'])
            : '';

        if ($class !== '' && $function !== '') {
            return $class . $type . $function;
        }

        if ($function !== '') {
            return $function;
        }

        return null;
    }
}
