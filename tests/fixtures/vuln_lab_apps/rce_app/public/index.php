<?php

declare(strict_types=1);

$cmd = (string) ($_GET['cmd'] ?? 'echo safe');
$sink = strtolower(trim((string) ($_GET['sink'] ?? 'system')));

final class PttUnserializeExec
{
    public string $cmd = '';

    public function __destruct()
    {
        if ($this->cmd === '') {
            return;
        }

        @system($this->cmd);
    }
}

function ptt_unserialize_payload_from_command(string $command): string
{
    $escaped = addslashes($command);
    return sprintf(
        'O:%d:"PttUnserializeExec":1:{s:3:"cmd";s:%d:"%s";}',
        strlen('PttUnserializeExec'),
        strlen($command),
        $escaped
    );
}

/**
 * The php -S SAPI does not execute dl() paths the same way as CLI.
 * Use an instrumented CLI sidecar so remote strict assertions can
 * exercise dl() deterministically while keeping the HTTP fixture shape.
 */
function invokeDlViaCliSidecar(string $moduleName): bool
{
    $phpBinary = (string) (PHP_BINARY ?? '');
    $extensionPath = (string) (getenv('PHP_TAINT_TRACE_LAB_EXT_PATH') ?: '');
    $prependPath = (string) (getenv('PHP_TAINT_TRACE_LAB_PREPEND_PATH') ?: '');
    $findingsPath = (string) (getenv('PHP_TAINT_TRACE_FINDINGS_FILE') ?: '');

    if ($phpBinary === '' || $extensionPath === '' || $prependPath === '' || $findingsPath === '') {
        return false;
    }

    $cliScript = <<<'PHP'
$moduleName = (string) ($argv[1] ?? "");
@dl($moduleName);
echo "sink_invoked:dl";
PHP;

    $command = escapeshellarg($phpBinary)
        . ' -n'
        . ' -d ' . escapeshellarg('extension=' . $extensionPath)
        . ' -d ' . escapeshellarg('auto_prepend_file=' . $prependPath)
        . ' -r ' . escapeshellarg($cliScript)
        . ' ' . escapeshellarg($moduleName);

    $descriptors = array(
        0 => array('pipe', 'r'),
        1 => array('pipe', 'w'),
        2 => array('pipe', 'w'),
    );
    $env = array(
        'PHP_TAINT_TRACE_ENABLED' => (string) (getenv('PHP_TAINT_TRACE_ENABLED') ?: '1'),
        'PHP_TAINT_TRACE_FINDINGS_FILE' => $findingsPath,
        'PHP_TAINT_TRACE_ERROR_LOG' => (string) (getenv('PHP_TAINT_TRACE_ERROR_LOG') ?: '0'),
        'PHP_TAINT_TRACE_CLEAR_AFTER_FLUSH' => (string) (getenv('PHP_TAINT_TRACE_CLEAR_AFTER_FLUSH') ?: '1'),
        'PHP_TAINT_TRACE_ENABLE_OPCODE_HOOKS' => (string) (getenv('PHP_TAINT_TRACE_ENABLE_OPCODE_HOOKS') ?: '1'),
        'PHP_TAINT_TRACE_OPCODE_HOOK_PROFILE' => (string) (getenv('PHP_TAINT_TRACE_OPCODE_HOOK_PROFILE') ?: 'full'),
    );

    $process = @proc_open($command, $descriptors, $pipes, null, $env);
    if (!is_resource($process)) {
        return false;
    }

    if (is_resource($pipes[0])) {
        fclose($pipes[0]);
    }
    $stdout = is_resource($pipes[1]) ? stream_get_contents($pipes[1]) : '';
    $stderr = is_resource($pipes[2]) ? stream_get_contents($pipes[2]) : '';
    if (is_resource($pipes[1])) {
        fclose($pipes[1]);
    }
    if (is_resource($pipes[2])) {
        fclose($pipes[2]);
    }

    $exitCode = proc_close($process);
    if (is_string($stdout) && $stdout !== '') {
        echo trim($stdout);
    }
    if ($exitCode !== 0 && is_string($stderr) && $stderr !== '') {
        echo "\n" . trim($stderr);
    }

    return true;
}

if ($sink === 'mail') {
    // Intentionally passes attacker-controlled additional mail parameters (arg 5).
    @mail('noreply@example.test', 'ptt', 'body', '', $cmd);
    echo 'mail attempted';
    return;
}

if ($sink === 'exec') {
    @exec($cmd, $output, $exitCode);
    echo implode("\n", $output);
    return;
}

if ($sink === 'shell_exec') {
    $output = @shell_exec($cmd);
    echo is_string($output) ? $output : '';
    return;
}

if ($sink === 'popen') {
    $handle = @popen($cmd, 'r');
    if (!is_resource($handle)) {
        echo 'popen failed';
        return;
    }

    $output = stream_get_contents($handle);
    pclose($handle);
    echo is_string($output) ? $output : '';
    return;
}

if ($sink === 'passthru') {
    ob_start();
    @passthru($cmd, $exitCode);
    $output = ob_get_clean();
    echo is_string($output) ? $output : '';
    return;
}

if ($sink === 'proc_open') {
    $descriptors = array(
        0 => array('pipe', 'r'),
        1 => array('pipe', 'w'),
        2 => array('pipe', 'w'),
    );
    $process = @proc_open($cmd, $descriptors, $pipes);
    if (!is_resource($process)) {
        echo 'proc_open failed';
        return;
    }

    if (is_resource($pipes[0])) {
        fclose($pipes[0]);
    }
    $stdout = is_resource($pipes[1]) ? stream_get_contents($pipes[1]) : '';
    $stderr = is_resource($pipes[2]) ? stream_get_contents($pipes[2]) : '';
    if (is_resource($pipes[1])) {
        fclose($pipes[1]);
    }
    if (is_resource($pipes[2])) {
        fclose($pipes[2]);
    }
    @proc_close($process);

    echo (is_string($stdout) ? $stdout : '') . (is_string($stderr) ? $stderr : '');
    return;
}

if ($sink === 'unserialize_template') {
    $payload = ptt_unserialize_payload_from_command($cmd);
    @unserialize($payload, array('allowed_classes' => array('PttUnserializeExec')));
    echo 'sink_invoked:unserialize_template';
    return;
}

if ($sink === 'eval') {
    // Intentionally unsafe evaluation of user-controlled PHP code.
    @eval($cmd);
    echo 'sink_invoked:eval';
    return;
}

if ($sink === 'pcntl_exec') {
    if (!function_exists('pcntl_exec')) {
        echo 'extension_unavailable:pcntl_exec';
        return;
    }

    // Intentionally routes tainted path argument to pcntl_exec for sink coverage.
    @pcntl_exec($cmd);
    echo 'sink_invoked:pcntl_exec';
    return;
}

if ($sink === 'expect_popen') {
    if (!function_exists('expect_popen')) {
        echo 'extension_unavailable:expect_popen';
        return;
    }

    $handle = @expect_popen($cmd);
    if (is_resource($handle)) {
        fclose($handle);
    }
    echo 'sink_invoked:expect_popen';
    return;
}

if ($sink === 'dl') {
    if (invokeDlViaCliSidecar($cmd)) {
        return;
    }

    if (!function_exists('dl')) {
        echo 'extension_unavailable:dl';
        return;
    }

    @dl($cmd);
    echo 'sink_invoked:dl';
    return;
}

system($cmd);
