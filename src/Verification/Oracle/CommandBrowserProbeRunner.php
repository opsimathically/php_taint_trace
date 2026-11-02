<?php

declare(strict_types=1);

namespace PhpTaintTrace\Verification\Oracle;

final class CommandBrowserProbeRunner implements BrowserProbeRunnerInterface
{
    public function __construct(
        private readonly string $commandTemplate
    ) {
    }

    public function probe(BrowserProbeRequest $request): BrowserProbeResult
    {
        if (trim($this->commandTemplate) === '') {
            return new BrowserProbeResult(
                success: false,
                executionObserved: false,
                error: 'browser probe command template is empty',
                exitCode: null,
                stdout: '',
                stderr: '',
                metadata: array()
            );
        }

        $renderedCommand = strtr($this->commandTemplate, array(
            '{url}' => escapeshellarg($request->url()),
            '{nonce}' => escapeshellarg($request->nonce()),
            '{timeout_ms}' => escapeshellarg((string) $request->timeoutMs()),
        ));

        $descriptorSpec = array(
            0 => array('pipe', 'r'),
            1 => array('pipe', 'w'),
            2 => array('pipe', 'w'),
        );

        $process = @proc_open(
            array('bash', '-lc', $renderedCommand),
            $descriptorSpec,
            $pipes
        );

        if (!is_resource($process)) {
            return new BrowserProbeResult(
                success: false,
                executionObserved: false,
                error: 'failed to launch browser probe command',
                exitCode: null,
                stdout: '',
                stderr: '',
                metadata: array(
                    'command' => $renderedCommand,
                )
            );
        }

        $stdout = '';
        $stderr = '';
        try {
            if (is_resource($pipes[0] ?? null)) {
                fclose($pipes[0]);
            }

            if (is_resource($pipes[1] ?? null)) {
                $stdout = stream_get_contents($pipes[1]) ?: '';
                fclose($pipes[1]);
            }

            if (is_resource($pipes[2] ?? null)) {
                $stderr = stream_get_contents($pipes[2]) ?: '';
                fclose($pipes[2]);
            }
        } finally {
            $exitCode = proc_close($process);
        }

        $trimmedStdout = trim($stdout);
        $decoded = $trimmedStdout !== '' ? json_decode($trimmedStdout, true) : null;
        if (!is_array($decoded)) {
            return new BrowserProbeResult(
                success: false,
                executionObserved: false,
                error: 'browser probe output was not valid JSON',
                exitCode: is_int($exitCode) ? $exitCode : null,
                stdout: $stdout,
                stderr: $stderr,
                metadata: array(
                    'command' => $renderedCommand,
                )
            );
        }

        $executed = filter_var(
            $decoded['executed'] ?? null,
            FILTER_VALIDATE_BOOL,
            FILTER_NULL_ON_FAILURE
        );
        if (!is_bool($executed)) {
            $observedNonce = isset($decoded['observed_nonce']) && is_scalar($decoded['observed_nonce'])
                ? (string) $decoded['observed_nonce']
                : null;
            $executed = is_string($observedNonce) && $observedNonce !== '' && hash_equals($request->nonce(), $observedNonce);
        }

        $success = (is_int($exitCode) ? $exitCode === 0 : false);
        if (isset($decoded['success'])) {
            $decodedSuccess = filter_var(
                $decoded['success'],
                FILTER_VALIDATE_BOOL,
                FILTER_NULL_ON_FAILURE
            );
            if (is_bool($decodedSuccess)) {
                $success = $success && $decodedSuccess;
            }
        }

        return new BrowserProbeResult(
            success: $success,
            executionObserved: $executed,
            error: isset($decoded['error']) && is_scalar($decoded['error']) ? (string) $decoded['error'] : null,
            exitCode: is_int($exitCode) ? $exitCode : null,
            stdout: $stdout,
            stderr: $stderr,
            metadata: array(
                'command' => $renderedCommand,
                'driver_output' => $decoded,
            )
        );
    }
}

