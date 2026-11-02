#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME_DIR="${ROOT_DIR}/.php_taint_trace_runtime/verifier_corpus"
CORPUS_DIR="${ROOT_DIR}/tests/fixtures/verification_corpus"
BASE_PORT=18080
CALLBACK_PORT=18081

usage() {
  cat <<'USAGE'
Usage: scripts/run_local_verifier_corpus.sh [--runtime-dir PATH] [--corpus-dir PATH] [--base-port PORT] [--callback-port PORT]

Runs the verifier worker against a deterministic local fixture using corpus-labeled jobs.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --runtime-dir)
      RUNTIME_DIR="$2"
      shift 2
      ;;
    --corpus-dir)
      CORPUS_DIR="$2"
      shift 2
      ;;
    --base-port)
      BASE_PORT="$2"
      shift 2
      ;;
    --callback-port)
      CALLBACK_PORT="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

for cmd in php mktemp; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "Missing required command: ${cmd}" >&2
    exit 1
  fi
done

if [[ ! -d "${CORPUS_DIR}" ]]; then
  echo "Corpus directory not found: ${CORPUS_DIR}" >&2
  exit 1
fi

TMP_ROOT="$(mktemp -d /tmp/php_taint_trace_verifier_corpus.XXXXXX)"
MAIN_DOCROOT="${TMP_ROOT}/main"
CALLBACK_DOCROOT="${TMP_ROOT}/callback"
mkdir -p "${MAIN_DOCROOT}" "${CALLBACK_DOCROOT}"

cat > "${MAIN_DOCROOT}/index.php" <<'PHP'
<?php

declare(strict_types=1);

/**
 * Percent-encode every byte so normalized decoders can recover the original token while
 * direct substring scans cannot.
 */
function ptt_percent_encode_all(string $value): string
{
    $encoded = '';
    $length = strlen($value);
    for ($index = 0; $index < $length; $index++) {
        $encoded .= sprintf('%%%02X', ord($value[$index]));
    }

    return $encoded;
}

function ptt_input(string $key, string $default = ''): string
{
    if (array_key_exists($key, $_GET)) {
        return (string) $_GET[$key];
    }
    if (array_key_exists($key, $_POST)) {
        return (string) $_POST[$key];
    }

    return $default;
}

/**
 * @return array{host: string, port: int, path: string}|null
 */
function ptt_parse_http_target(string $url): ?array
{
    $parts = parse_url($url);
    if (!is_array($parts)) {
        return null;
    }

    $scheme = strtolower((string) ($parts['scheme'] ?? ''));
    if ($scheme !== 'http') {
        return null;
    }

    $host = (string) ($parts['host'] ?? '');
    if ($host === '') {
        return null;
    }

    $port = (int) ($parts['port'] ?? 80);
    if ($port <= 0 || $port > 65535) {
        return null;
    }

    $path = (string) ($parts['path'] ?? '/');
    if ($path === '') {
        $path = '/';
    }
    $query = (string) ($parts['query'] ?? '');
    if ($query !== '') {
        $path .= '?' . $query;
    }

    return array(
        'host' => $host,
        'port' => $port,
        'path' => $path,
    );
}

function ptt_fetch_http_via_stream_socket_client(string $url): string|false
{
    $target = ptt_parse_http_target($url);
    if ($target === null) {
        return false;
    }

    $socket = @stream_socket_client(
        sprintf('tcp://%s:%d', $target['host'], $target['port']),
        $errno,
        $errstr,
        1.0
    );
    if (!is_resource($socket)) {
        return false;
    }

    stream_set_timeout($socket, 1);
    $request = sprintf(
        "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
        $target['path'],
        $target['host']
    );
    fwrite($socket, $request);
    $response = stream_get_contents($socket);
    fclose($socket);

    if (!is_string($response) || $response === '') {
        return false;
    }

    $split = explode("\r\n\r\n", $response, 2);
    return $split[1] ?? '';
}

function ptt_fetch_http_via_pfsockopen(string $url): string|false
{
    $target = ptt_parse_http_target($url);
    if ($target === null) {
        return false;
    }

    $socket = @pfsockopen($target['host'], $target['port'], $errno, $errstr, 1.0);
    if (!is_resource($socket)) {
        return false;
    }

    stream_set_timeout($socket, 1);
    $request = sprintf(
        "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
        $target['path'],
        $target['host']
    );
    fwrite($socket, $request);
    $response = stream_get_contents($socket);
    fclose($socket);

    if (!is_string($response) || $response === '') {
        return false;
    }

    $split = explode("\r\n\r\n", $response, 2);
    return $split[1] ?? '';
}

function ptt_fetch_http_via_fsockopen(string $url): string|false
{
    $target = ptt_parse_http_target($url);
    if ($target === null) {
        return false;
    }

    $socket = @fsockopen($target['host'], $target['port'], $errno, $errstr, 1.0);
    if (!is_resource($socket)) {
        return false;
    }

    stream_set_timeout($socket, 1);
    $request = sprintf(
        "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
        $target['path'],
        $target['host']
    );
    fwrite($socket, $request);
    $response = stream_get_contents($socket);
    fclose($socket);

    if (!is_string($response) || $response === '') {
        return false;
    }

    $split = explode("\r\n\r\n", $response, 2);
    return $split[1] ?? '';
}

function ptt_fetch_headers_via_get_headers(string $url): string|false
{
    $headers = @get_headers($url, true);
    if (!is_array($headers) || $headers === array()) {
        return false;
    }

    $lines = array();
    foreach ($headers as $name => $value) {
        if (is_array($value)) {
            $lines[] = sprintf(
                '%s: %s',
                (string) $name,
                implode(', ', array_map(static fn (mixed $item): string => (string) $item, $value))
            );
            continue;
        }

        $lines[] = sprintf('%s: %s', (string) $name, (string) $value);
    }

    return implode("\n", $lines);
}

function ptt_fetch_http_via_curl(string $url, string $mode = 'setopt'): string|false
{
    if (!function_exists('curl_init') || !function_exists('curl_setopt') || !function_exists('curl_exec')) {
        return false;
    }

    $handle = @curl_init();
    if (!is_object($handle) && !is_resource($handle)) {
        return false;
    }

    @curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);
    @curl_setopt($handle, CURLOPT_FOLLOWLOCATION, false);
    @curl_setopt($handle, CURLOPT_CONNECTTIMEOUT, 1);
    @curl_setopt($handle, CURLOPT_TIMEOUT, 2);

    if ($mode === 'setopt_array' && function_exists('curl_setopt_array')) {
        @curl_setopt_array($handle, array(
            CURLOPT_URL => $url,
        ));
    } else {
        @curl_setopt($handle, CURLOPT_URL, $url);
    }

    $body = @curl_exec($handle);
    if (is_object($handle) || is_resource($handle)) {
        @curl_close($handle);
    }

    return is_string($body) ? $body : false;
}

function ptt_fetch_http_via_curl_multi(string $url, string $mode = 'setopt'): string|false
{
    if (
        !function_exists('curl_init')
        || !function_exists('curl_setopt')
        || !function_exists('curl_exec')
        || !function_exists('curl_multi_init')
        || !function_exists('curl_multi_add_handle')
        || !function_exists('curl_multi_exec')
        || !function_exists('curl_multi_getcontent')
    ) {
        return false;
    }

    $handle = @curl_init();
    if (!is_object($handle) && !is_resource($handle)) {
        return false;
    }

    @curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);
    @curl_setopt($handle, CURLOPT_FOLLOWLOCATION, false);
    @curl_setopt($handle, CURLOPT_CONNECTTIMEOUT, 1);
    @curl_setopt($handle, CURLOPT_TIMEOUT, 2);

    if ($mode === 'setopt_array' && function_exists('curl_setopt_array')) {
        @curl_setopt_array($handle, array(
            CURLOPT_URL => $url,
        ));
    } else {
        @curl_setopt($handle, CURLOPT_URL, $url);
    }

    $multiHandle = @curl_multi_init();
    if (!is_object($multiHandle) && !is_resource($multiHandle)) {
        @curl_close($handle);
        return false;
    }

    @curl_multi_add_handle($multiHandle, $handle);
    $running = 0;
    for ($attempt = 0; $attempt < 20; $attempt++) {
        $status = @curl_multi_exec($multiHandle, $running);
        if (!is_int($status) || $running <= 0) {
            break;
        }

        if (function_exists('curl_multi_select')) {
            @curl_multi_select($multiHandle, 0.2);
            continue;
        }

        usleep(10_000);
    }
    $body = @curl_multi_getcontent($handle);
    @curl_multi_remove_handle($multiHandle, $handle);
    @curl_multi_close($multiHandle);
    @curl_close($handle);

    return is_string($body) ? $body : false;
}

function ptt_ssrf_touch_soapclient(string $url, string $mode = 'wsdl'): void
{
    if (!class_exists('SoapClient')) {
        return;
    }

    try {
        if ($mode === 'setlocation') {
            $client = @new SoapClient(null, array(
                'location' => 'http://127.0.0.1:9/',
                'uri' => 'urn:ptt:local',
                'connection_timeout' => 1,
                'exceptions' => true,
                'trace' => false,
            ));
            if ($client instanceof SoapClient) {
                @$client->__setLocation($url);
                @$client->__soapCall('ping', array());
            }
            return;
        }

        if ($mode === 'location') {
            @new SoapClient(null, array(
                'location' => $url,
                'uri' => 'urn:ptt:local',
                'connection_timeout' => 1,
                'exceptions' => true,
                'trace' => false,
            ));
            return;
        }

        @new SoapClient($url, array(
            'cache_wsdl' => defined('WSDL_CACHE_NONE') ? WSDL_CACHE_NONE : 0,
            'connection_timeout' => 1,
            'exceptions' => true,
            'trace' => false,
        ));
    } catch (Throwable) {
        // Intentionally swallow fixture sink errors.
    }
}

function ptt_sqli_touch_sqlsrv_prepare(string $query): void
{
    if (!function_exists('sqlsrv_prepare')) {
        return;
    }

    try {
        @sqlsrv_prepare(null, $query);
    } catch (Throwable) {
        // Intentionally swallow fixture sink errors.
    }
}

function ptt_sqli_touch_mysqli_execute_query(string $query): void
{
    if (!function_exists('mysqli_execute_query') || !function_exists('mysqli_init')) {
        return;
    }

    if (function_exists('mysqli_report') && defined('MYSQLI_REPORT_OFF')) {
        @mysqli_report(MYSQLI_REPORT_OFF);
    }

    $conn = @mysqli_init();
    if (!($conn instanceof mysqli)) {
        return;
    }

    try {
        @mysqli_options($conn, MYSQLI_OPT_CONNECT_TIMEOUT, 1);
        @mysqli_real_connect($conn, '127.0.0.1', 'php_taint', 'php_taint_password', 'php_taint_lab', 3306);
        @mysqli_execute_query($conn, $query);
    } catch (Throwable) {
        // Intentionally swallow fixture sink errors.
    } finally {
        @mysqli_close($conn);
    }
}

function ptt_sqli_touch_pdo_query(string $query): void
{
    if (!class_exists('PDO')) {
        return;
    }

    try {
        $pdo = new PDO('sqlite::memory:');
        @$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_SILENT);
        @$pdo->query($query);
    } catch (Throwable) {
        // Intentionally swallow fixture sink errors.
    }
}

function ptt_sqli_touch_pdo_exec(string $query): void
{
    if (!class_exists('PDO')) {
        return;
    }

    try {
        $pdo = new PDO('sqlite::memory:');
        @$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_SILENT);
        @$pdo->exec($query);
    } catch (Throwable) {
        // Intentionally swallow fixture sink errors.
    }
}

function ptt_sqli_touch_sqlite3_querysingle(string $query): void
{
    if (!class_exists('SQLite3')) {
        return;
    }

    try {
        $db = new SQLite3(':memory:');
        @$db->querySingle($query);
        @$db->close();
    } catch (Throwable) {
        // Intentionally swallow fixture sink errors.
    }
}

function ptt_sqli_touch_sqlite3_query(string $query): void
{
    if (!class_exists('SQLite3')) {
        return;
    }

    try {
        $db = new SQLite3(':memory:');
        $result = @$db->query($query);
        if ($result instanceof SQLite3Result) {
            @$result->finalize();
        }
        @$db->close();
    } catch (Throwable) {
        // Intentionally swallow fixture sink errors.
    }
}

function ptt_sqli_touch_sqlite3_exec(string $query): void
{
    if (!class_exists('SQLite3')) {
        return;
    }

    try {
        $db = new SQLite3(':memory:');
        @$db->exec($query);
        @$db->close();
    } catch (Throwable) {
        // Intentionally swallow fixture sink errors.
    }
}

function ptt_xxe_extract_entity_url(string $xml): ?string
{
    if (preg_match('/<!ENTITY\s+[a-zA-Z0-9_:-]+\s+SYSTEM\s+["\']([^"\']+)["\']\s*>/i', $xml, $matches) !== 1) {
        return null;
    }

    $url = trim((string) ($matches[1] ?? ''));
    if ($url === '') {
        return null;
    }

    return $url;
}

function ptt_xxe_extract_root_text(string $xml): string
{
    if (preg_match('/<root[^>]*>(.*?)<\/root>/is', $xml, $matches) === 1) {
        return trim((string) ($matches[1] ?? ''));
    }

    return trim($xml);
}

function ptt_xxe_resolve_external_entity(string $xml): string|false
{
    $entityUrl = ptt_xxe_extract_entity_url($xml);
    if ($entityUrl === null) {
        return ptt_xxe_extract_root_text($xml);
    }

    $body = @file_get_contents($entityUrl);
    if ($body === false) {
        return false;
    }

    if (!is_string($body)) {
        return false;
    }

    return trim($body);
}

function ptt_xxe_touch_sink(string $xml, string $sink): void
{
    try {
        if ($sink === 'dom_load' || $sink === 'domdocument_load') {
            $document = new DOMDocument();
            @$document->load($xml);
            return;
        }

        if ($sink === 'dom_loadxml' || $sink === 'domdocument_loadxml') {
            $document = new DOMDocument();
            @$document->loadXML($xml);
            return;
        }

        if ($sink === 'xmlreader_open') {
            $reader = new XMLReader();
            @$reader->open($xml);
            @$reader->close();
            return;
        }

        if ($sink === 'xmlreader_xml') {
            $reader = new XMLReader();
            @$reader->XML($xml);
            @$reader->close();
            return;
        }

        if ($sink === 'simplexml_file' || $sink === 'simplexml_load_file') {
            @simplexml_load_file($xml);
            return;
        }

        if ($sink === 'simplexml' || $sink === 'simplexml_load_string') {
            @simplexml_load_string($xml);
            return;
        }

        @simplexml_load_string($xml);
    } catch (Throwable) {
        // Intentionally swallow parser errors in this fixture.
    }
}

function ptt_rce_allowlisted_command(string $candidate): string
{
    $allowlist = array(
        'status' => 'echo safe-status',
        'health' => 'echo safe-health',
    );

    return $allowlist[$candidate] ?? 'echo blocked';
}

function ptt_rce_exec_output(string $command): string
{
    $output = array();
    @exec($command, $output, $exitCode);
    return implode("\n", $output);
}

function ptt_rce_shell_exec_output(string $command): string
{
    $output = @shell_exec($command);
    return is_string($output) ? $output : '';
}

function ptt_rce_popen_output(string $command): string
{
    $handle = @popen($command, 'r');
    if (!is_resource($handle)) {
        return '';
    }

    $output = stream_get_contents($handle);
    pclose($handle);

    return is_string($output) ? $output : '';
}

function ptt_rce_passthru_output(string $command): string
{
    ob_start();
    @passthru($command, $exitCode);
    $output = ob_get_clean();
    return is_string($output) ? $output : '';
}

function ptt_rce_proc_open_output(string $command): string
{
    $descriptors = array(
        0 => array('pipe', 'r'),
        1 => array('pipe', 'w'),
        2 => array('pipe', 'w'),
    );
    $process = @proc_open($command, $descriptors, $pipes);
    if (!is_resource($process)) {
        return '';
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

    return (is_string($stdout) ? $stdout : '') . (is_string($stderr) ? $stderr : '');
}

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

function ptt_rce_unserialize_payload(string $command): string
{
    $escaped = addslashes($command);
    return sprintf(
        'O:%d:"PttUnserializeExec":1:{s:3:"cmd";s:%d:"%s";}',
        strlen('PttUnserializeExec'),
        strlen($command),
        $escaped
    );
}

function ptt_rce_unserialize_output(string $command): string
{
    $payload = ptt_rce_unserialize_payload($command);
    ob_start();
    @unserialize($payload, array('allowed_classes' => array('PttUnserializeExec')));
    $output = ob_get_clean();
    return is_string($output) ? $output : '';
}

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
if ($path === '/rce') {
    $cmd = ptt_input('cmd', 'echo safe');
    system($cmd);
    return;
}

if ($path === '/rce_safe') {
    $cmd = ptt_input('cmd', 'status');
    $selected = ptt_rce_allowlisted_command($cmd);
    system($selected);
    return;
}

if ($path === '/rce_exec') {
    $cmd = ptt_input('cmd', 'echo safe');
    echo ptt_rce_exec_output($cmd);
    return;
}

if ($path === '/rce_exec_safe') {
    $cmd = ptt_input('cmd', 'status');
    echo ptt_rce_exec_output(ptt_rce_allowlisted_command($cmd));
    return;
}

if ($path === '/rce_shell_exec') {
    $cmd = ptt_input('cmd', 'echo safe');
    echo ptt_rce_shell_exec_output($cmd);
    return;
}

if ($path === '/rce_shell_exec_safe') {
    $cmd = ptt_input('cmd', 'status');
    echo ptt_rce_shell_exec_output(ptt_rce_allowlisted_command($cmd));
    return;
}

if ($path === '/rce_popen') {
    $cmd = ptt_input('cmd', 'echo safe');
    echo ptt_rce_popen_output($cmd);
    return;
}

if ($path === '/rce_popen_safe') {
    $cmd = ptt_input('cmd', 'status');
    echo ptt_rce_popen_output(ptt_rce_allowlisted_command($cmd));
    return;
}

if ($path === '/rce_passthru') {
    $cmd = ptt_input('cmd', 'echo safe');
    echo ptt_rce_passthru_output($cmd);
    return;
}

if ($path === '/rce_passthru_safe') {
    $cmd = ptt_input('cmd', 'status');
    echo ptt_rce_passthru_output(ptt_rce_allowlisted_command($cmd));
    return;
}

if ($path === '/rce_proc_open') {
    $cmd = ptt_input('cmd', 'echo safe');
    echo ptt_rce_proc_open_output($cmd);
    return;
}

if ($path === '/rce_proc_open_safe') {
    $cmd = ptt_input('cmd', 'status');
    echo ptt_rce_proc_open_output(ptt_rce_allowlisted_command($cmd));
    return;
}

if ($path === '/rce_unserialize_template') {
    $cmd = ptt_input('cmd', 'echo safe');
    echo ptt_rce_unserialize_output($cmd);
    return;
}

if ($path === '/rce_unserialize_template_safe') {
    $cmd = ptt_input('cmd', 'status');
    echo ptt_rce_unserialize_output(ptt_rce_allowlisted_command($cmd));
    return;
}

if ($path === '/rce_eval') {
    $cmd = ptt_input('cmd', 'echo "safe";');
    ob_start();
    try {
        @eval($cmd);
    } catch (Throwable) {
        ob_end_clean();
        http_response_code(500);
        echo 'eval failed';
        return;
    }
    $output = ob_get_clean();
    echo is_string($output) ? $output : '';
    return;
}

if ($path === '/rce_eval_safe') {
    $cmd = ptt_input('cmd', 'echo "safe";');
    if (preg_match('/^echo\\s+"[a-z0-9_\\- ]+";$/i', $cmd) !== 1) {
        http_response_code(403);
        echo 'blocked';
        return;
    }

    ob_start();
    @eval('echo "allowed";');
    $output = ob_get_clean();
    echo is_string($output) ? $output : '';
    return;
}

if ($path === '/rce_fp_normalized') {
    $cmd = ptt_input('cmd', 'echo safe');
    echo ptt_percent_encode_all($cmd);
    return;
}

if ($path === '/rce_tricky_confirmed') {
    $cmd = ptt_input('cmd', 'echo safe');
    if (!str_starts_with($cmd, 'echo ')) {
        http_response_code(403);
        echo 'blocked';
        return;
    }
    if (preg_match('/[;$`|&]/', $cmd) === 1) {
        http_response_code(403);
        echo 'blocked';
        return;
    }

    system($cmd);
    return;
}

if ($path === '/rce_fp_allowlist_alias') {
    $cmd = ptt_input('cmd', '');
    $alias = strtolower(strtok(trim($cmd), " \t\r\n") ?: '');
    system(ptt_rce_allowlisted_command($alias));
    return;
}

if ($path === '/rce_exec_tricky_confirmed') {
    $cmd = ptt_input('cmd', 'echo safe');
    if (!str_starts_with($cmd, 'echo ')) {
        http_response_code(403);
        echo 'blocked';
        return;
    }
    if (preg_match('/[;$`|&]/', $cmd) === 1) {
        http_response_code(403);
        echo 'blocked';
        return;
    }

    echo ptt_rce_exec_output($cmd);
    return;
}

if ($path === '/rce_exec_safe_guarded') {
    $cmd = ptt_input('cmd', '');
    $alias = strtolower(strtok(trim($cmd), " \t\r\n") ?: '');
    echo ptt_rce_exec_output(ptt_rce_allowlisted_command($alias));
    return;
}

if ($path === '/rce_proc_open_tricky_confirmed') {
    $cmd = ptt_input('cmd', 'echo safe');
    if (!str_starts_with($cmd, 'echo ')) {
        http_response_code(403);
        echo 'blocked';
        return;
    }
    if (preg_match('/[;$`|&]/', $cmd) === 1) {
        http_response_code(403);
        echo 'blocked';
        return;
    }

    echo ptt_rce_proc_open_output($cmd);
    return;
}

if ($path === '/rce_proc_open_safe_guarded') {
    $cmd = ptt_input('cmd', '');
    $alias = strtolower(strtok(trim($cmd), " \t\r\n") ?: '');
    echo ptt_rce_proc_open_output(ptt_rce_allowlisted_command($alias));
    return;
}

if ($path === '/rce_unserialize_template_tricky_confirmed') {
    $cmd = ptt_input('cmd', 'echo safe');
    if (!str_starts_with($cmd, 'echo ')) {
        http_response_code(403);
        echo 'blocked';
        return;
    }
    if (preg_match('/[;$`|&]/', $cmd) === 1) {
        http_response_code(403);
        echo 'blocked';
        return;
    }

    echo ptt_rce_unserialize_output($cmd);
    return;
}

if ($path === '/rce_unserialize_template_safe_guarded') {
    $cmd = ptt_input('cmd', '');
    $alias = strtolower(strtok(trim($cmd), " \t\r\n") ?: '');
    echo ptt_rce_unserialize_output(ptt_rce_allowlisted_command($alias));
    return;
}

if ($path === '/rce_eval_tricky_confirmed') {
    $cmd = ptt_input('cmd', 'echo "safe";');
    if (str_contains(strtolower($cmd), 'system(')) {
        http_response_code(403);
        echo 'blocked';
        return;
    }

    ob_start();
    try {
        @eval($cmd);
    } catch (Throwable) {
        ob_end_clean();
        http_response_code(500);
        echo 'eval failed';
        return;
    }
    $output = ob_get_clean();
    echo is_string($output) ? $output : '';
    return;
}

if ($path === '/rce_eval_safe_guarded') {
    $cmd = ptt_input('cmd', '');
    if (preg_match('/^echo\\s+"[a-z0-9_\\- ]+";$/i', $cmd) !== 1) {
        http_response_code(403);
        echo 'blocked';
        return;
    }

    ob_start();
    @eval('echo "allowed";');
    $output = ob_get_clean();
    echo is_string($output) ? $output : '';
    return;
}

if ($path === '/rce_tricky_decode_after_check') {
    $cmdRaw = ptt_input('cmd', 'echo safe');
    if (preg_match('/[;&|`$]/', $cmdRaw) === 1) {
        http_response_code(403);
        echo 'blocked';
        return;
    }

    $cmd = rawurldecode($cmdRaw);
    system($cmd);
    return;
}

if ($path === '/rce_mail_arg5_vuln') {
    $subject = ptt_input('subject', 'status');
    $cmd = ptt_input('cmd', 'echo safe-mail');
    if ($subject === '') {
        http_response_code(400);
        echo 'subject missing';
        return;
    }

    system($cmd);
    return;
}

if ($path === '/ssrf') {
    $url = ptt_input('url', 'http://127.0.0.1:9/');
    $body = @file_get_contents($url);
    if ($body === false) {
        http_response_code(502);
        echo 'fetch failed';
        return;
    }

    echo $body;
    return;
}

if ($path === '/ssrf_stream_socket_client') {
    $url = ptt_input('url', 'http://127.0.0.1:9/');
    $body = ptt_fetch_http_via_stream_socket_client($url);
    if (!is_string($body) || $body === '') {
        http_response_code(502);
        echo 'fetch failed';
        return;
    }

    echo $body;
    return;
}

if ($path === '/ssrf_curl_setopt') {
    $url = ptt_input('url', 'http://127.0.0.1:9/');
    $body = ptt_fetch_http_via_curl($url, 'setopt');
    if (!is_string($body) || $body === '') {
        http_response_code(502);
        echo 'fetch failed';
        return;
    }

    echo $body;
    return;
}

if ($path === '/ssrf_curl_setopt_safe') {
    $url = ptt_input('url', '');
    if (!str_starts_with($url, 'http://127.0.0.1:18080/safe-allow')) {
        http_response_code(403);
        echo 'fetch blocked';
        return;
    }

    $body = ptt_fetch_http_via_curl($url, 'setopt');
    if (!is_string($body) || $body === '') {
        http_response_code(502);
        echo 'fetch failed';
        return;
    }

    echo $body;
    return;
}

if ($path === '/ssrf_curl_setopt_array') {
    $url = ptt_input('url', 'http://127.0.0.1:9/');
    $body = ptt_fetch_http_via_curl($url, 'setopt_array');
    if (!is_string($body) || $body === '') {
        http_response_code(502);
        echo 'fetch failed';
        return;
    }

    echo $body;
    return;
}

if ($path === '/ssrf_curl_setopt_array_safe') {
    $url = ptt_input('url', '');
    if (!str_starts_with($url, 'http://127.0.0.1:18080/safe-allow')) {
        http_response_code(403);
        echo 'fetch blocked';
        return;
    }

    $body = ptt_fetch_http_via_curl($url, 'setopt_array');
    if (!is_string($body) || $body === '') {
        http_response_code(502);
        echo 'fetch failed';
        return;
    }

    echo $body;
    return;
}

if ($path === '/ssrf_curl_multi_setopt') {
    $url = ptt_input('url', 'http://127.0.0.1:9/');
    $body = ptt_fetch_http_via_curl_multi($url, 'setopt');
    if (!is_string($body) || $body === '') {
        http_response_code(502);
        echo 'fetch failed';
        return;
    }

    echo $body;
    return;
}

if ($path === '/ssrf_curl_multi_setopt_safe') {
    $url = ptt_input('url', '');
    if (!str_starts_with($url, 'http://127.0.0.1:18080/safe-allow')) {
        http_response_code(403);
        echo 'fetch blocked';
        return;
    }

    $body = ptt_fetch_http_via_curl_multi($url, 'setopt');
    if (!is_string($body) || $body === '') {
        http_response_code(502);
        echo 'fetch failed';
        return;
    }

    echo $body;
    return;
}

if ($path === '/ssrf_curl_multi_setopt_array') {
    $url = ptt_input('url', 'http://127.0.0.1:9/');
    $body = ptt_fetch_http_via_curl_multi($url, 'setopt_array');
    if (!is_string($body) || $body === '') {
        http_response_code(502);
        echo 'fetch failed';
        return;
    }

    echo $body;
    return;
}

if ($path === '/ssrf_curl_multi_setopt_array_safe') {
    $url = ptt_input('url', '');
    if (!str_starts_with($url, 'http://127.0.0.1:18080/safe-allow')) {
        http_response_code(403);
        echo 'fetch blocked';
        return;
    }

    $body = ptt_fetch_http_via_curl_multi($url, 'setopt_array');
    if (!is_string($body) || $body === '') {
        http_response_code(502);
        echo 'fetch failed';
        return;
    }

    echo $body;
    return;
}

if ($path === '/ssrf_stream_socket_client_safe') {
    $url = ptt_input('url', '');
    if (!str_starts_with($url, 'http://127.0.0.1:18080/safe-allow')) {
        http_response_code(403);
        echo 'fetch blocked';
        return;
    }

    $body = ptt_fetch_http_via_stream_socket_client($url);
    if (!is_string($body) || $body === '') {
        http_response_code(502);
        echo 'fetch failed';
        return;
    }

    echo $body;
    return;
}

if ($path === '/ssrf_pfsockopen') {
    $url = ptt_input('url', 'http://127.0.0.1:9/');
    $body = ptt_fetch_http_via_pfsockopen($url);
    if (!is_string($body) || $body === '') {
        http_response_code(502);
        echo 'fetch failed';
        return;
    }

    echo $body;
    return;
}

if ($path === '/ssrf_pfsockopen_safe') {
    $url = ptt_input('url', '');
    if (!str_starts_with($url, 'http://127.0.0.1:18080/safe-allow')) {
        http_response_code(403);
        echo 'fetch blocked';
        return;
    }

    $body = ptt_fetch_http_via_pfsockopen($url);
    if (!is_string($body) || $body === '') {
        http_response_code(502);
        echo 'fetch failed';
        return;
    }

    echo $body;
    return;
}

if ($path === '/ssrf_fsockopen') {
    $url = ptt_input('url', 'http://127.0.0.1:9/');
    $body = ptt_fetch_http_via_fsockopen($url);
    if (!is_string($body) || $body === '') {
        http_response_code(502);
        echo 'fetch failed';
        return;
    }

    echo $body;
    return;
}

if ($path === '/ssrf_fsockopen_safe') {
    $url = ptt_input('url', '');
    if (!str_starts_with($url, 'http://127.0.0.1:18080/safe-allow')) {
        http_response_code(403);
        echo 'fetch blocked';
        return;
    }

    $body = ptt_fetch_http_via_fsockopen($url);
    if (!is_string($body) || $body === '') {
        http_response_code(502);
        echo 'fetch failed';
        return;
    }

    echo $body;
    return;
}

if ($path === '/ssrf_get_headers') {
    $url = ptt_input('url', 'http://127.0.0.1:9/');
    $body = ptt_fetch_headers_via_get_headers($url);
    if (!is_string($body) || $body === '') {
        http_response_code(502);
        echo 'fetch failed';
        return;
    }

    echo $body;
    return;
}

if ($path === '/ssrf_get_headers_safe') {
    $url = ptt_input('url', '');
    if (!str_starts_with($url, 'http://127.0.0.1:18080/safe-allow')) {
        http_response_code(403);
        echo 'fetch blocked';
        return;
    }

    $body = ptt_fetch_headers_via_get_headers($url);
    if (!is_string($body) || $body === '') {
        http_response_code(502);
        echo 'fetch failed';
        return;
    }

    echo $body;
    return;
}

if ($path === '/ssrf_soapclient_construct') {
    $url = ptt_input('url', 'http://127.0.0.1:9/');
    ptt_ssrf_touch_soapclient($url);

    $body = @file_get_contents($url);
    if ($body === false) {
        http_response_code(502);
        echo 'fetch failed';
        return;
    }

    echo $body;
    return;
}

if ($path === '/ssrf_soapclient_construct_safe') {
    $url = ptt_input('url', '');
    ptt_ssrf_touch_soapclient($url);

    if (!str_starts_with($url, 'http://127.0.0.1:18080/safe-allow')) {
        http_response_code(403);
        echo 'fetch blocked';
        return;
    }

    $body = @file_get_contents($url);
    if ($body === false) {
        http_response_code(502);
        echo 'fetch failed';
        return;
    }

    echo $body;
    return;
}

if ($path === '/ssrf_soapclient_construct_location') {
    $url = ptt_input('url', 'http://127.0.0.1:9/');
    ptt_ssrf_touch_soapclient($url, 'location');

    $body = @file_get_contents($url);
    if ($body === false) {
        http_response_code(502);
        echo 'fetch failed';
        return;
    }

    echo $body;
    return;
}

if ($path === '/ssrf_soapclient_construct_location_safe') {
    $url = ptt_input('url', '');
    ptt_ssrf_touch_soapclient($url, 'location');

    if (!str_starts_with($url, 'http://127.0.0.1:18080/safe-allow')) {
        http_response_code(403);
        echo 'fetch blocked';
        return;
    }

    $body = @file_get_contents($url);
    if ($body === false) {
        http_response_code(502);
        echo 'fetch failed';
        return;
    }

    echo $body;
    return;
}

if ($path === '/ssrf_soapclient_setlocation') {
    $url = ptt_input('url', 'http://127.0.0.1:9/');
    ptt_ssrf_touch_soapclient($url, 'setlocation');

    $body = @file_get_contents($url);
    if ($body === false) {
        http_response_code(502);
        echo 'fetch failed';
        return;
    }

    echo $body;
    return;
}

if ($path === '/ssrf_soapclient_setlocation_safe') {
    $url = ptt_input('url', '');
    ptt_ssrf_touch_soapclient($url, 'setlocation');

    if (!str_starts_with($url, 'http://127.0.0.1:18080/safe-allow')) {
        http_response_code(403);
        echo 'fetch blocked';
        return;
    }

    $body = @file_get_contents($url);
    if ($body === false) {
        http_response_code(502);
        echo 'fetch failed';
        return;
    }

    echo $body;
    return;
}

if ($path === '/ssrf_wrapper_file_get_contents') {
    $pathInput = ptt_input('path', 'http://127.0.0.1:9/');
    $body = @file_get_contents($pathInput);
    if ($body === false) {
        http_response_code(502);
        echo 'fetch failed';
        return;
    }

    echo $body;
    return;
}

if ($path === '/ssrf_wrapper_file_get_contents_safe') {
    $pathInput = ptt_input('path', '');
    if (!str_starts_with($pathInput, 'http://127.0.0.1:18080/safe-allow')) {
        http_response_code(403);
        echo 'fetch blocked';
        return;
    }

    $body = @file_get_contents($pathInput);
    if ($body === false) {
        http_response_code(502);
        echo 'fetch failed';
        return;
    }

    echo $body;
    return;
}

if ($path === '/ssrf_wrapper_fopen') {
    $pathInput = ptt_input('path', 'http://127.0.0.1:9/');
    $handle = @fopen($pathInput, 'rb');
    if (!is_resource($handle)) {
        http_response_code(502);
        echo 'fetch failed';
        return;
    }

    $body = stream_get_contents($handle);
    fclose($handle);
    if (!is_string($body) || $body === '') {
        http_response_code(502);
        echo 'fetch failed';
        return;
    }

    echo $body;
    return;
}

if ($path === '/ssrf_wrapper_fopen_safe') {
    $pathInput = ptt_input('path', '');
    if (!str_starts_with($pathInput, 'http://127.0.0.1:18080/safe-allow')) {
        http_response_code(403);
        echo 'fetch blocked';
        return;
    }

    $handle = @fopen($pathInput, 'rb');
    if (!is_resource($handle)) {
        http_response_code(502);
        echo 'fetch failed';
        return;
    }

    $body = stream_get_contents($handle);
    fclose($handle);
    if (!is_string($body) || $body === '') {
        http_response_code(502);
        echo 'fetch failed';
        return;
    }

    echo $body;
    return;
}

if ($path === '/ssrf_wrapper_readfile') {
    $pathInput = ptt_input('path', 'http://127.0.0.1:9/');
    ob_start();
    $bytesRead = @readfile($pathInput);
    $body = ob_get_clean();
    if (!is_int($bytesRead) || $bytesRead <= 0 || !is_string($body) || $body === '') {
        http_response_code(502);
        echo 'fetch failed';
        return;
    }

    echo $body;
    return;
}

if ($path === '/ssrf_wrapper_readfile_safe') {
    $pathInput = ptt_input('path', '');
    if (!str_starts_with($pathInput, 'http://127.0.0.1:18080/safe-allow')) {
        http_response_code(403);
        echo 'fetch blocked';
        return;
    }

    ob_start();
    $bytesRead = @readfile($pathInput);
    $body = ob_get_clean();
    if (!is_int($bytesRead) || $bytesRead <= 0 || !is_string($body) || $body === '') {
        http_response_code(502);
        echo 'fetch failed';
        return;
    }

    echo $body;
    return;
}

if ($path === '/ssrf_safe') {
    $url = ptt_input('url', '');
    if (!str_starts_with($url, 'http://127.0.0.1:18080/safe-allow')) {
        http_response_code(403);
        echo 'fetch blocked';
        return;
    }

    $body = @file_get_contents($url);
    if ($body === false) {
        http_response_code(502);
        echo 'fetch failed';
        return;
    }

    echo $body;
    return;
}

if ($path === '/ssrf_fp_normalized') {
    $url = ptt_input('url', '');
    echo ptt_percent_encode_all($url);
    return;
}

if ($path === '/ssrf_tricky_confirmed') {
    $url = ptt_input('url', '');
    $parts = parse_url($url);
    $host = is_array($parts) ? (string) ($parts['host'] ?? '') : '';
    if ($host !== '127.0.0.1') {
        http_response_code(403);
        echo 'fetch blocked';
        return;
    }

    $body = @file_get_contents($url);
    if ($body === false) {
        http_response_code(502);
        echo 'fetch failed';
        return;
    }

    echo $body;
    return;
}

if ($path === '/ssrf_fp_metadata_probe') {
    $url = ptt_input('url', '');
    $parts = parse_url($url);
    $host = is_array($parts) ? (string) ($parts['host'] ?? '') : '';
    $scheme = is_array($parts) ? (string) ($parts['scheme'] ?? '') : '';
    printf('probe host=%s scheme=%s', $host, $scheme);
    return;
}

if ($path === '/ssrf_tricky_dns_guarded_confirmed') {
    $url = ptt_input('url', '');
    $parts = parse_url($url);
    $host = is_array($parts) ? (string) ($parts['host'] ?? '') : '';
    if (preg_match('/^\d+\.\d+\.\d+\.\d+$/', $host) !== 1) {
        http_response_code(403);
        echo 'fetch blocked';
        return;
    }
    if (!str_starts_with($host, '127.')) {
        http_response_code(403);
        echo 'fetch blocked';
        return;
    }

    $body = @file_get_contents($url);
    if ($body === false) {
        http_response_code(502);
        echo 'fetch failed';
        return;
    }

    echo $body;
    return;
}

if ($path === '/ssrf_fsockopen_tricky_confirmed') {
    $url = ptt_input('url', '');
    $parts = parse_url($url);
    $host = is_array($parts) ? (string) ($parts['host'] ?? '') : '';
    if (!str_starts_with($host, '127.')) {
        http_response_code(403);
        echo 'fetch blocked';
        return;
    }

    $body = ptt_fetch_http_via_fsockopen($url);
    if (!is_string($body) || $body === '') {
        http_response_code(502);
        echo 'fetch failed';
        return;
    }

    echo $body;
    return;
}

if ($path === '/ssrf_fsockopen_safe_guarded') {
    $url = ptt_input('url', '');
    $parts = parse_url($url);
    if (!is_array($parts)) {
        http_response_code(403);
        echo 'fetch blocked';
        return;
    }

    $scheme = strtolower((string) ($parts['scheme'] ?? ''));
    $host = (string) ($parts['host'] ?? '');
    $port = (int) ($parts['port'] ?? 80);
    $pathPart = (string) ($parts['path'] ?? '/');
    if ($scheme !== 'http' || $host !== '127.0.0.1' || $port !== 18080 || !str_starts_with($pathPart, '/safe-allow')) {
        http_response_code(403);
        echo 'fetch blocked';
        return;
    }

    $body = ptt_fetch_http_via_fsockopen($url);
    if (!is_string($body) || $body === '') {
        http_response_code(502);
        echo 'fetch failed';
        return;
    }

    echo $body;
    return;
}

if ($path === '/ssrf_get_headers_tricky_confirmed') {
    $url = ptt_input('url', '');
    $parts = parse_url($url);
    $host = is_array($parts) ? (string) ($parts['host'] ?? '') : '';
    if ($host !== '127.0.0.1') {
        http_response_code(403);
        echo 'fetch blocked';
        return;
    }

    $body = ptt_fetch_headers_via_get_headers($url);
    if (!is_string($body) || $body === '') {
        http_response_code(502);
        echo 'fetch failed';
        return;
    }

    echo $body;
    return;
}

if ($path === '/ssrf_get_headers_safe_guarded') {
    $url = ptt_input('url', '');
    $parts = parse_url($url);
    if (!is_array($parts)) {
        http_response_code(403);
        echo 'fetch blocked';
        return;
    }

    $scheme = strtolower((string) ($parts['scheme'] ?? ''));
    $host = (string) ($parts['host'] ?? '');
    $port = (int) ($parts['port'] ?? 80);
    $pathPart = (string) ($parts['path'] ?? '/');
    if ($scheme !== 'http' || $host !== '127.0.0.1' || $port !== 18080 || !str_starts_with($pathPart, '/safe-allow')) {
        http_response_code(403);
        echo 'fetch blocked';
        return;
    }

    $body = ptt_fetch_headers_via_get_headers($url);
    if (!is_string($body) || $body === '') {
        http_response_code(502);
        echo 'fetch failed';
        return;
    }

    echo $body;
    return;
}

if ($path === '/sqli') {
    $query = ptt_input('q', '1');
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

if ($path === '/sqli_pg_query_prepared') {
    $query = ptt_input('q', '1');
    if (preg_match("/UNION\\s+SELECT\\s+'([^']+)'/i", $query, $matches) === 1) {
        echo $matches[1];
        return;
    }
    if (preg_match("/SELECT\\s+'([^']+)'\\s+AS\\s+username/i", $query, $matches) === 1) {
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

if ($path === '/sqli_pg_query_prepared_safe') {
    $query = ptt_input('q', '1');
    $id = (int) $query;
    if ($id === 1) {
        echo 'alice';
        return;
    }

    echo 'no rows';
    return;
}

if ($path === '/sqli_safe') {
    $query = ptt_input('q', '1');
    $id = (int) $query;
    if ($id === 1) {
        echo 'alice';
        return;
    }

    echo 'no rows';
    return;
}

if ($path === '/sqli_sqlsrv_prepare') {
    $query = ptt_input('q', '1');
    ptt_sqli_touch_sqlsrv_prepare($query);

    if (preg_match("/UNION\\s+SELECT\\s+'([^']+)'/i", $query, $matches) === 1) {
        echo $matches[1];
        return;
    }
    if (preg_match("/SELECT\\s+'([^']+)'\\s+AS\\s+username/i", $query, $matches) === 1) {
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

if ($path === '/sqli_sqlsrv_prepare_safe') {
    $query = ptt_input('q', '1');
    ptt_sqli_touch_sqlsrv_prepare('SELECT username FROM users WHERE id = ?');

    $id = (int) $query;
    if ($id === 1) {
        echo 'alice';
        return;
    }

    echo 'no rows';
    return;
}

if ($path === '/sqli_mysqli_execute_query') {
    $query = ptt_input('q', '1');
    ptt_sqli_touch_mysqli_execute_query($query);

    if (preg_match("/UNION\\s+SELECT\\s+'([^']+)'/i", $query, $matches) === 1) {
        echo $matches[1];
        return;
    }
    if (preg_match("/SELECT\\s+'([^']+)'\\s+AS\\s+username/i", $query, $matches) === 1) {
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

if ($path === '/sqli_mysqli_execute_query_safe') {
    $query = ptt_input('q', '1');
    ptt_sqli_touch_mysqli_execute_query('SELECT username FROM users WHERE id = ?');

    $id = (int) $query;
    if ($id === 1) {
        echo 'alice';
        return;
    }

    echo 'no rows';
    return;
}

if ($path === '/sqli_fp_normalized') {
    $query = ptt_input('q', '1');
    echo ptt_percent_encode_all($query);
    return;
}

if ($path === '/sqli_tricky_confirmed') {
    $query = ptt_input('q', '1');
    if (preg_match('/^\d+$/', $query) === 1) {
        if ($query === '1') {
            echo 'alice';
            return;
        }

        echo 'no rows';
        return;
    }

    if (stripos($query, 'UNION SELECT') !== false && preg_match("/UNION\\s+SELECT\\s+'([^']+)'/i", $query, $matches) === 1) {
        echo $matches[1];
        return;
    }

    echo 'no rows';
    return;
}

if ($path === '/sqli_fp_token_filter_safe') {
    $query = ptt_input('q', '1');
    $normalized = preg_replace('/[^a-zA-Z0-9_ ]/', '', $query) ?? '';
    if ($normalized === '1') {
        echo 'alice';
        return;
    }

    echo 'no rows';
    return;
}

if ($path === '/sqli_tricky_cast_then_fallback') {
    $query = ptt_input('q', '1');
    $validated = filter_var($query, FILTER_VALIDATE_INT);
    if ($validated !== false) {
        if ((int) $validated === 1) {
            echo 'alice';
            return;
        }

        echo 'no rows';
        return;
    }

    $probe = preg_replace('/\s+/', ' ', trim($query)) ?? $query;
    if (preg_match("/UNION\\s+SELECT\\s+'([^']+)'/i", $probe, $matches) === 1) {
        echo $matches[1];
        return;
    }
    if (preg_match("/SELECT\\s+'([^']+)'\\s+AS\\s+username/i", $probe, $matches) === 1) {
        echo $matches[1];
        return;
    }

    echo 'no rows';
    return;
}

if ($path === '/sqli_mysqli_execute_query_tricky_confirmed') {
    $query = ptt_input('q', '1');
    ptt_sqli_touch_mysqli_execute_query($query);

    if (preg_match('/^\d+$/', $query) === 1) {
        if ($query === '1') {
            echo 'alice';
            return;
        }

        echo 'no rows';
        return;
    }

    $probe = preg_replace('/\s+/', ' ', trim($query)) ?? $query;
    if (preg_match("/UNION\\s+SELECT\\s+'([^']+)'/i", $probe, $matches) === 1) {
        echo $matches[1];
        return;
    }
    if (preg_match("/SELECT\\s+'([^']+)'\\s+AS\\s+username/i", $probe, $matches) === 1) {
        echo $matches[1];
        return;
    }

    echo 'no rows';
    return;
}

if ($path === '/sqli_mysqli_execute_query_safe_guarded') {
    $query = ptt_input('q', '1');
    ptt_sqli_touch_mysqli_execute_query('SELECT username FROM users WHERE id = ?');
    $id = (int) $query;
    if ($id === 1) {
        echo 'alice';
        return;
    }

    echo 'no rows';
    return;
}

if ($path === '/sqli_pdo_query') {
    $query = ptt_input('q', '1');
    ptt_sqli_touch_pdo_query($query);

    if (preg_match("/UNION\\s+SELECT\\s+'([^']+)'/i", $query, $matches) === 1) {
        echo $matches[1];
        return;
    }
    if (preg_match("/SELECT\\s+'([^']+)'\\s+AS\\s+username/i", $query, $matches) === 1) {
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

if ($path === '/sqli_pdo_exec') {
    $query = ptt_input('q', '1');
    ptt_sqli_touch_pdo_exec($query);

    if (preg_match("/UNION\\s+SELECT\\s+'([^']+)'/i", $query, $matches) === 1) {
        echo $matches[1];
        return;
    }
    if (preg_match("/SELECT\\s+'([^']+)'\\s+AS\\s+username/i", $query, $matches) === 1) {
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

if ($path === '/sqli_pdo_exec_safe') {
    $query = ptt_input('q', '1');
    ptt_sqli_touch_pdo_exec('CREATE TABLE ptt_safe(id INTEGER PRIMARY KEY)');

    $id = (int) $query;
    if ($id === 1) {
        echo 'alice';
        return;
    }

    echo 'no rows';
    return;
}

if ($path === '/sqli_pdo_query_safe') {
    $query = ptt_input('q', '1');
    ptt_sqli_touch_pdo_query('SELECT username FROM users WHERE id = 1');

    $id = (int) $query;
    if ($id === 1) {
        echo 'alice';
        return;
    }

    echo 'no rows';
    return;
}

if ($path === '/sqli_pdo_query_tricky_confirmed') {
    $query = ptt_input('q', '1');
    ptt_sqli_touch_pdo_query($query);

    if (preg_match('/^\d+$/', $query) === 1) {
        if ($query === '1') {
            echo 'alice';
            return;
        }

        echo 'no rows';
        return;
    }

    $probe = preg_replace('/\s+/', ' ', trim($query)) ?? $query;
    if (preg_match("/UNION\\s+SELECT\\s+'([^']+)'/i", $probe, $matches) === 1) {
        echo $matches[1];
        return;
    }
    if (preg_match("/SELECT\\s+'([^']+)'\\s+AS\\s+username/i", $probe, $matches) === 1) {
        echo $matches[1];
        return;
    }

    echo 'no rows';
    return;
}

if ($path === '/sqli_pdo_exec_tricky_confirmed') {
    $query = ptt_input('q', '1');
    ptt_sqli_touch_pdo_exec($query);

    if (preg_match('/^\d+$/', $query) === 1) {
        if ($query === '1') {
            echo 'alice';
            return;
        }

        echo 'no rows';
        return;
    }

    $probe = preg_replace('/\s+/', ' ', trim($query)) ?? $query;
    if (preg_match("/UNION\\s+SELECT\\s+'([^']+)'/i", $probe, $matches) === 1) {
        echo $matches[1];
        return;
    }
    if (preg_match("/SELECT\\s+'([^']+)'\\s+AS\\s+username/i", $probe, $matches) === 1) {
        echo $matches[1];
        return;
    }

    echo 'no rows';
    return;
}

if ($path === '/sqli_pdo_query_safe_guarded') {
    $query = ptt_input('q', '1');
    ptt_sqli_touch_pdo_query('SELECT username FROM users WHERE id = 1');
    $id = (int) $query;
    if ($id === 1) {
        echo 'alice';
        return;
    }

    echo 'no rows';
    return;
}

if ($path === '/sqli_pdo_exec_safe_guarded') {
    $query = ptt_input('q', '1');
    ptt_sqli_touch_pdo_exec('CREATE TABLE ptt_safe(id INTEGER PRIMARY KEY)');
    $id = (int) $query;
    if ($id === 1) {
        echo 'alice';
        return;
    }

    echo 'no rows';
    return;
}

if ($path === '/sqli_sqlite3_querysingle') {
    $query = ptt_input('q', '1');
    ptt_sqli_touch_sqlite3_querysingle($query);

    if (preg_match("/UNION\\s+SELECT\\s+'([^']+)'/i", $query, $matches) === 1) {
        echo $matches[1];
        return;
    }
    if (preg_match("/SELECT\\s+'([^']+)'\\s+AS\\s+username/i", $query, $matches) === 1) {
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

if ($path === '/sqli_sqlite3_query') {
    $query = ptt_input('q', '1');
    ptt_sqli_touch_sqlite3_query($query);

    if (preg_match("/UNION\\s+SELECT\\s+'([^']+)'/i", $query, $matches) === 1) {
        echo $matches[1];
        return;
    }
    if (preg_match("/SELECT\\s+'([^']+)'\\s+AS\\s+username/i", $query, $matches) === 1) {
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

if ($path === '/sqli_sqlite3_query_safe') {
    $query = ptt_input('q', '1');
    ptt_sqli_touch_sqlite3_query('SELECT 1');
    $id = (int) $query;
    if ($id === 1) {
        echo 'alice';
        return;
    }

    echo 'no rows';
    return;
}

if ($path === '/sqli_sqlite3_exec') {
    $query = ptt_input('q', '1');
    ptt_sqli_touch_sqlite3_exec($query);

    if (preg_match("/UNION\\s+SELECT\\s+'([^']+)'/i", $query, $matches) === 1) {
        echo $matches[1];
        return;
    }
    if (preg_match("/SELECT\\s+'([^']+)'\\s+AS\\s+username/i", $query, $matches) === 1) {
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

if ($path === '/sqli_sqlite3_exec_safe') {
    $query = ptt_input('q', '1');
    ptt_sqli_touch_sqlite3_exec('CREATE TABLE ptt_safe(id INTEGER PRIMARY KEY)');
    $id = (int) $query;
    if ($id === 1) {
        echo 'alice';
        return;
    }

    echo 'no rows';
    return;
}

if ($path === '/sqli_sqlite3_querysingle_safe') {
    $query = ptt_input('q', '1');
    ptt_sqli_touch_sqlite3_querysingle('SELECT 1');
    $id = (int) $query;
    if ($id === 1) {
        echo 'alice';
        return;
    }

    echo 'no rows';
    return;
}

if ($path === '/sqli_sqlite3_querysingle_tricky_confirmed') {
    $query = ptt_input('q', '1');
    ptt_sqli_touch_sqlite3_querysingle($query);

    if (preg_match('/^\d+$/', $query) === 1) {
        if ($query === '1') {
            echo 'alice';
            return;
        }

        echo 'no rows';
        return;
    }

    $probe = preg_replace('/\s+/', ' ', trim($query)) ?? $query;
    if (preg_match("/UNION\\s+SELECT\\s+'([^']+)'/i", $probe, $matches) === 1) {
        echo $matches[1];
        return;
    }
    if (preg_match("/SELECT\\s+'([^']+)'\\s+AS\\s+username/i", $probe, $matches) === 1) {
        echo $matches[1];
        return;
    }

    echo 'no rows';
    return;
}

if ($path === '/sqli_sqlite3_query_tricky_confirmed') {
    $query = ptt_input('q', '1');
    ptt_sqli_touch_sqlite3_query($query);

    if (preg_match('/^\d+$/', $query) === 1) {
        if ($query === '1') {
            echo 'alice';
            return;
        }

        echo 'no rows';
        return;
    }

    $probe = preg_replace('/\s+/', ' ', trim($query)) ?? $query;
    if (preg_match("/UNION\\s+SELECT\\s+'([^']+)'/i", $probe, $matches) === 1) {
        echo $matches[1];
        return;
    }
    if (preg_match("/SELECT\\s+'([^']+)'\\s+AS\\s+username/i", $probe, $matches) === 1) {
        echo $matches[1];
        return;
    }

    echo 'no rows';
    return;
}

if ($path === '/sqli_sqlite3_exec_tricky_confirmed') {
    $query = ptt_input('q', '1');
    ptt_sqli_touch_sqlite3_exec($query);

    if (preg_match('/^\d+$/', $query) === 1) {
        if ($query === '1') {
            echo 'alice';
            return;
        }

        echo 'no rows';
        return;
    }

    $probe = preg_replace('/\s+/', ' ', trim($query)) ?? $query;
    if (preg_match("/UNION\\s+SELECT\\s+'([^']+)'/i", $probe, $matches) === 1) {
        echo $matches[1];
        return;
    }
    if (preg_match("/SELECT\\s+'([^']+)'\\s+AS\\s+username/i", $probe, $matches) === 1) {
        echo $matches[1];
        return;
    }

    echo 'no rows';
    return;
}

if ($path === '/sqli_sqlite3_querysingle_safe_guarded') {
    $query = ptt_input('q', '1');
    ptt_sqli_touch_sqlite3_querysingle('SELECT 1');
    $id = (int) $query;
    if ($id === 1) {
        echo 'alice';
        return;
    }

    echo 'no rows';
    return;
}

if ($path === '/sqli_sqlite3_query_safe_guarded') {
    $query = ptt_input('q', '1');
    ptt_sqli_touch_sqlite3_query('SELECT 1');
    $id = (int) $query;
    if ($id === 1) {
        echo 'alice';
        return;
    }

    echo 'no rows';
    return;
}

if ($path === '/sqli_sqlite3_exec_safe_guarded') {
    $query = ptt_input('q', '1');
    ptt_sqli_touch_sqlite3_exec('CREATE TABLE ptt_safe(id INTEGER PRIMARY KEY)');
    $id = (int) $query;
    if ($id === 1) {
        echo 'alice';
        return;
    }

    echo 'no rows';
    return;
}

if ($path === '/file') {
    $requestedPath = ptt_input('path', '/etc/hostname');
    if ($requestedPath === '/etc/hostname') {
        echo "fixture-host\n";
        return;
    }

    http_response_code(500);
    echo 'read failed';
    return;
}

if ($path === '/file_fopen') {
    $requestedPath = ptt_input('path', '/etc/hostname');
    $handle = @fopen($requestedPath, 'r');
    if (!is_resource($handle)) {
        http_response_code(500);
        echo 'read failed';
        return;
    }

    $contents = stream_get_contents($handle);
    fclose($handle);
    if (!is_string($contents) || trim($contents) === '') {
        http_response_code(500);
        echo 'read failed';
        return;
    }

    echo $contents;
    return;
}

if ($path === '/file_fopen_safe') {
    $requestedPath = ptt_input('path', '/etc/hostname');
    if ($requestedPath !== '/var/app/allowed.txt') {
        http_response_code(403);
        echo 'read failed';
        return;
    }

    echo "allowed-file\n";
    return;
}

if ($path === '/file_readfile') {
    $requestedPath = ptt_input('path', '/etc/hostname');
    ob_start();
    $bytesRead = @readfile($requestedPath);
    $body = ob_get_clean();
    if (!is_int($bytesRead) || $bytesRead <= 0 || !is_string($body) || trim($body) === '') {
        http_response_code(500);
        echo 'read failed';
        return;
    }

    echo $body;
    return;
}

if ($path === '/file_readfile_safe') {
    $requestedPath = ptt_input('path', '/etc/hostname');
    if ($requestedPath !== '/var/app/allowed.txt') {
        http_response_code(403);
        echo 'read failed';
        return;
    }

    echo "allowed-file\n";
    return;
}

if ($path === '/file_spl_vuln') {
    $requestedPath = ptt_input('path', '/etc/hostname');
    try {
        $file = new SplFileObject($requestedPath, 'r');
        $line = $file->fgets();
        if (!is_string($line) || trim($line) === '') {
            http_response_code(500);
            echo 'read failed';
            return;
        }

        echo trim($line) . "\n";
        return;
    } catch (Throwable) {
        http_response_code(500);
        echo 'read failed';
        return;
    }
}

if ($path === '/file_spl_safe') {
    $requestedPath = ptt_input('path', '/etc/hostname');
    if ($requestedPath !== '/var/app/allowed.txt') {
        http_response_code(403);
        echo 'read failed';
        return;
    }

    echo "allowed-file\n";
    return;
}

if ($path === '/file_safe') {
    $requestedPath = ptt_input('path', '/etc/hostname');
    if ($requestedPath !== '/var/app/allowed.txt') {
        http_response_code(403);
        echo 'read failed';
        return;
    }

    echo "allowed-file\n";
    return;
}

if ($path === '/file_fopen_tricky_confirmed') {
    $requestedPath = ptt_input('path', '/etc/hostname');
    if (str_contains($requestedPath, '..') || str_contains($requestedPath, "\0")) {
        http_response_code(403);
        echo 'read failed';
        return;
    }
    $handle = @fopen($requestedPath, 'r');
    if (!is_resource($handle)) {
        http_response_code(500);
        echo 'read failed';
        return;
    }

    $contents = stream_get_contents($handle);
    fclose($handle);
    if (!is_string($contents) || trim($contents) === '') {
        http_response_code(500);
        echo 'read failed';
        return;
    }

    echo $contents;
    return;
}

if ($path === '/file_fopen_safe_guarded') {
    $requestedPath = ptt_input('path', '/etc/hostname');
    $normalized = rawurldecode($requestedPath);
    if (!str_starts_with($normalized, '/srv/public/')) {
        http_response_code(403);
        echo 'read failed';
        return;
    }

    echo "allowed-file\n";
    return;
}

if ($path === '/file_readfile_tricky_confirmed') {
    $requestedPath = ptt_input('path', '/etc/hostname');
    if (str_contains($requestedPath, '..') || str_contains($requestedPath, "\0")) {
        http_response_code(403);
        echo 'read failed';
        return;
    }
    ob_start();
    $bytesRead = @readfile($requestedPath);
    $body = ob_get_clean();
    if (!is_int($bytesRead) || $bytesRead <= 0 || !is_string($body) || trim($body) === '') {
        http_response_code(500);
        echo 'read failed';
        return;
    }

    echo $body;
    return;
}

if ($path === '/file_readfile_safe_guarded') {
    $requestedPath = ptt_input('path', '/etc/hostname');
    $normalized = rawurldecode($requestedPath);
    if (!str_starts_with($normalized, '/srv/public/')) {
        http_response_code(403);
        echo 'read failed';
        return;
    }

    echo "allowed-file\n";
    return;
}

if ($path === '/file_fp_mixed') {
    echo "fixture-host read failed\n";
    return;
}

if ($path === '/file_tricky_confirmed') {
    $requestedPath = ptt_input('path', '/etc/hostname');
    if (str_contains($requestedPath, '..') || str_contains($requestedPath, "\0")) {
        http_response_code(403);
        echo 'read failed';
        return;
    }
    if (!str_starts_with($requestedPath, '/')) {
        http_response_code(403);
        echo 'read failed';
        return;
    }
    if ($requestedPath === '/etc/hostname') {
        echo "fixture-host\n";
        return;
    }

    http_response_code(500);
    echo 'read failed';
    return;
}

if ($path === '/file_fp_guarded_safe') {
    $requestedPath = ptt_input('path', '/etc/hostname');
    $normalized = rawurldecode($requestedPath);
    if (!str_starts_with($normalized, '/srv/public/')) {
        http_response_code(403);
        echo 'read failed';
        return;
    }

    echo "allowed-file\n";
    return;
}

if ($path === '/file_tricky_basename_confirmed') {
    $requestedPath = ptt_input('path', '/etc/hostname');
    $requestedPath = str_replace("\0", '', $requestedPath);
    $base = basename($requestedPath);
    if ($base === 'hostname') {
        echo "fixture-host\n";
        return;
    }

    http_response_code(500);
    echo 'read failed';
    return;
}

if ($path === '/xss') {
    $name = ptt_input('name', 'guest');
    printf('Hello %s', $name);
    return;
}

if ($path === '/xss_safe') {
    $name = ptt_input('name', 'guest');
    echo 'Hello ' . htmlspecialchars($name, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    return;
}

if ($path === '/xss_fp_normalized') {
    $name = ptt_input('name', 'guest');
    echo ptt_percent_encode_all($name);
    return;
}

if ($path === '/xss_tricky_confirmed') {
    $name = ptt_input('name', 'guest');
    $name = preg_replace('/on[a-z]+\\s*=\\s*/i', '', $name) ?? $name;
    printf('<div class="hello">%s</div>', $name);
    return;
}

if ($path === '/xss_fp_strip_tags_safe') {
    $name = ptt_input('name', 'guest');
    echo 'Hello ' . strip_tags($name);
    return;
}

if ($path === '/xss_tricky_encode_decode_confirmed') {
    $name = ptt_input('name', 'guest');
    $encoded = rawurlencode($name);
    if (str_contains($encoded, '<script>')) {
        $encoded = 'blocked';
    }

    echo 'Hello ' . urldecode($encoded);
    return;
}

if ($path === '/idor') {
    $resourceId = ptt_input('resource_id', '42');
    $actorId = ptt_input('actor_id', '1043');
    $mode = ptt_input('mode', 'vuln');
    $owner = (string) ((int) $resourceId + 1000);

    if ($mode === 'safe' && $actorId !== $owner) {
        http_response_code(403);
        echo 'forbidden';
        return;
    }

    printf('resource:%s owner:%s actor:%s mode:%s', $resourceId, $owner, $actorId, $mode);
    return;
}

if ($path === '/idor_safe') {
    $resourceId = ptt_input('resource_id', '42');
    $actorId = ptt_input('actor_id', '1043');
    $owner = (string) ((int) $resourceId + 1000);

    if ($actorId !== $owner) {
        http_response_code(403);
        echo 'forbidden';
        return;
    }

    printf('resource:%s owner:%s actor:%s mode:safe', $resourceId, $owner, $actorId);
    return;
}

if ($path === '/idor_fp_mixed') {
    $resourceId = ptt_input('resource_id', '42');
    $actorId = ptt_input('actor_id', '1043');
    $mode = ptt_input('mode', 'vuln');
    $owner = (string) ((int) $resourceId + 1000);
    printf('resource:%s owner:%s actor:%s mode:%s forbidden', $resourceId, $owner, $actorId, $mode);
    return;
}

if ($path === '/idor_tricky_confirmed') {
    $resourceId = ptt_input('resource_id', '42');
    $actorId = ptt_input('actor_id', '1043');
    $mode = ptt_input('mode', 'vuln');
    $owner = (string) ((int) $resourceId + 1000);
    $role = ptt_input('role', 'user');

    if ($mode === 'safe' && $actorId !== $owner && $role !== 'support') {
        http_response_code(403);
        echo 'forbidden';
        return;
    }

    printf('resource:%s owner:%s actor:%s mode:%s role:%s', $resourceId, $owner, $actorId, $mode, $role);
    return;
}

if ($path === '/idor_fp_strict_safe') {
    $resourceId = ptt_input('resource_id', '42');
    $actorId = ptt_input('actor_id', '1043');
    $mode = ptt_input('mode', 'vuln');
    $owner = (string) ((int) $resourceId + 1000);

    if ($actorId !== $owner) {
        http_response_code(403);
        printf('forbidden resource:%s actor:%s mode:%s', $resourceId, $actorId, $mode);
        return;
    }

    printf('resource:%s owner:%s actor:%s mode:%s', $resourceId, $owner, $actorId, $mode);
    return;
}

if ($path === '/idor_tricky_token_bypass_confirmed') {
    $resourceId = ptt_input('resource_id', '42');
    $actorId = ptt_input('actor_id', '1043');
    $mode = ptt_input('mode', 'vuln');
    $owner = (string) ((int) $resourceId + 1000);
    $authzToken = ptt_input('authz_token', '');
    $expectedToken = substr(sha1($resourceId), 0, 8);

    if ($mode === 'safe' && $actorId !== $owner && !hash_equals($expectedToken, $authzToken)) {
        http_response_code(403);
        echo 'forbidden';
        return;
    }

    printf('resource:%s owner:%s actor:%s mode:%s token:%s', $resourceId, $owner, $actorId, $mode, $authzToken);
    return;
}

if ($path === '/xxe') {
    $xml = ptt_input('xml', '<root>safe</root>');
    $sink = strtolower(ptt_input('sink', 'simplexml'));
    ptt_xxe_touch_sink($xml, $sink);
    $resolved = ptt_xxe_resolve_external_entity($xml);
    if ($resolved === false) {
        http_response_code(502);
        echo 'xml fetch failed';
        return;
    }

    echo $resolved;
    return;
}

if ($path === '/xxe_safe') {
    $xml = ptt_input('xml', '<root>safe</root>');
    $sink = strtolower(ptt_input('sink', 'simplexml'));
    ptt_xxe_touch_sink($xml, $sink);
    if (stripos($xml, '<!ENTITY') !== false || stripos($xml, '<!DOCTYPE') !== false) {
        http_response_code(403);
        echo 'entity blocked';
        return;
    }

    echo ptt_xxe_extract_root_text($xml);
    return;
}

echo 'ok';
PHP

cat > "${CALLBACK_DOCROOT}/index.php" <<'PHP'
<?php

declare(strict_types=1);

$name = (string) ($_GET['name'] ?? 'guest');
header('X-PTT-Name: ' . $name);
printf('Hello %s', $name);
PHP

MAIN_PID=""
CALLBACK_PID=""
cleanup() {
  if [[ -n "${MAIN_PID}" ]]; then
    kill "${MAIN_PID}" >/dev/null 2>&1 || true
    wait "${MAIN_PID}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${CALLBACK_PID}" ]]; then
    kill "${CALLBACK_PID}" >/dev/null 2>&1 || true
    wait "${CALLBACK_PID}" >/dev/null 2>&1 || true
  fi
  rm -rf "${TMP_ROOT}"
}
trap cleanup EXIT

wait_for_port() {
  local port="$1"
  for _ in $(seq 1 80); do
    if php -r '
$fp = @fsockopen("127.0.0.1", (int) $argv[1], $errno, $errstr, 0.1);
if ($fp !== false) {
    fclose($fp);
    exit(0);
}
exit(1);
' "${port}"; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

php -S "127.0.0.1:${BASE_PORT}" -t "${MAIN_DOCROOT}" >/dev/null 2>&1 &
MAIN_PID="$!"
php -S "127.0.0.1:${CALLBACK_PORT}" -t "${CALLBACK_DOCROOT}" >/dev/null 2>&1 &
CALLBACK_PID="$!"

wait_for_port "${BASE_PORT}" || { echo "Fixture server failed to start on ${BASE_PORT}" >&2; exit 1; }
wait_for_port "${CALLBACK_PORT}" || { echo "Callback server failed to start on ${CALLBACK_PORT}" >&2; exit 1; }

rm -rf "${RUNTIME_DIR}"
mkdir -p "${RUNTIME_DIR}"

cd "${ROOT_DIR}"
php -r '
require $argv[1];

use PhpTaintTrace\Verification\Verifier\JsonlVerificationQueue;
use PhpTaintTrace\Verification\Model\VerificationJob;

$corpusDir = $argv[2];
$runtimeDir = $argv[3];
$queue = new JsonlVerificationQueue($runtimeDir);
$requirementsSummaryPath = rtrim($runtimeDir, "/") . "/scenario_requirements_summary.json";

$files = glob(rtrim($corpusDir, "/") . "/*.json");
if (!is_array($files) || $files === array()) {
    fwrite(STDERR, "verification corpus is empty" . PHP_EOL);
    exit(1);
}
sort($files);

$oracleMap = array(
    "rce" => "rce_oracle",
    "ssrf" => "ssrf_oracle",
    "sqli" => "sqli_oracle",
    "file" => "file_oracle",
    "xss" => "xss_oracle",
    "idor" => "idor_oracle",
    "xxe" => "xxe_oracle",
);

/**
 * @return list<string>
 */
$normalizeScalarList = static function (mixed $value): array {
    if (!is_array($value)) {
        return array();
    }

    $result = array();
    foreach ($value as $entry) {
        if (!is_scalar($entry)) {
            continue;
        }
        $normalized = trim((string) $entry);
        if ($normalized === "") {
            continue;
        }
        $result[] = $normalized;
    }

    return array_values(array_unique($result));
};

$totalScenarios = 0;
$queuedScenarios = 0;
$skippedScenarios = array();

foreach ($files as $file) {
    $payload = json_decode((string) file_get_contents($file), true);
    if (!is_array($payload)) {
        fwrite(STDERR, "invalid corpus json: " . $file . PHP_EOL);
        exit(1);
    }
    $totalScenarios++;

    $scenarioId = (string) ($payload["scenario_id"] ?? "");
    $category = (string) ($payload["category"] ?? "");
    $scenarioKind = (string) ($payload["scenario_kind"] ?? "");
    $expectedConfirmed = $payload["expected_confirmed"] ?? null;
    $corpusPhase = (string) ($payload["corpus_phase"] ?? "phase_d");
    $requestMethod = strtoupper((string) ($payload["request_method"] ?? "GET"));
    $endpoint = (string) ($payload["endpoint"] ?? "");
    $plan = is_array($payload["payload_plan"] ?? null) ? $payload["payload_plan"] : array();
    $targetParam = (string) ($plan["target_query_param"] ?? "");
    $targetBodyParam = (string) ($plan["target_body_param"] ?? "");
    $targetParamLocation = strtolower((string) ($plan["target_param_location"] ?? ""));

    if ($scenarioId === "" || $category === "" || $endpoint === "") {
        fwrite(STDERR, "missing required fields in corpus scenario: " . $file . PHP_EOL);
        exit(1);
    }
    if (!in_array($scenarioKind, array("vulnerable", "safe"), true)) {
        fwrite(STDERR, "invalid or missing scenario_kind in corpus scenario: " . $file . PHP_EOL);
        exit(1);
    }
    if (!is_bool($expectedConfirmed)) {
        fwrite(STDERR, "missing boolean expected_confirmed in corpus scenario: " . $file . PHP_EOL);
        exit(1);
    }
    if ($targetParam === "" && $targetBodyParam === "") {
        fwrite(STDERR, "missing target query/body parameter in corpus scenario: " . $file . PHP_EOL);
        exit(1);
    }
    if ($requestMethod === "") {
        fwrite(STDERR, "missing request_method in corpus scenario: " . $file . PHP_EOL);
        exit(1);
    }
    if ($targetParamLocation !== "" && !in_array($targetParamLocation, array("query", "body"), true)) {
        fwrite(STDERR, "invalid target_param_location in corpus scenario: " . $file . PHP_EOL);
        exit(1);
    }

    if (!array_key_exists($category, $oracleMap)) {
        fwrite(STDERR, "unsupported category in corpus scenario: " . $category . PHP_EOL);
        exit(1);
    }

    $requirements = is_array($payload["requires"] ?? null) ? $payload["requires"] : array();
    if (($payload["requires"] ?? null) !== null && !is_array($payload["requires"])) {
        fwrite(STDERR, "invalid requires object in corpus scenario: " . $file . PHP_EOL);
        exit(1);
    }
    $requiredExtensions = $normalizeScalarList($payload["requires_extensions"] ?? ($requirements["extensions"] ?? array()));
    $requiredFunctions = $normalizeScalarList($payload["requires_functions"] ?? ($requirements["functions"] ?? array()));
    $requiredClasses = $normalizeScalarList($payload["requires_classes"] ?? ($requirements["classes"] ?? array()));
    $requiredMethods = $normalizeScalarList($payload["requires_methods"] ?? ($requirements["methods"] ?? array()));

    $skipReasons = array();
    foreach ($requiredExtensions as $extensionName) {
        if (!extension_loaded($extensionName)) {
            $skipReasons[] = "missing_extension:" . $extensionName;
        }
    }
    foreach ($requiredFunctions as $functionName) {
        if (!function_exists($functionName)) {
            $skipReasons[] = "missing_function:" . $functionName;
        }
    }
    foreach ($requiredClasses as $className) {
        if (!class_exists($className)) {
            $skipReasons[] = "missing_class:" . $className;
        }
    }
    foreach ($requiredMethods as $methodSpec) {
        $parts = explode("::", $methodSpec, 2);
        if (count($parts) !== 2) {
            fwrite(STDERR, "invalid requires_methods entry in corpus scenario: " . $file . " => " . $methodSpec . PHP_EOL);
            exit(1);
        }

        $className = trim((string) $parts[0]);
        $methodName = trim((string) $parts[1]);
        if ($className === "" || $methodName === "") {
            fwrite(STDERR, "invalid requires_methods entry in corpus scenario: " . $file . " => " . $methodSpec . PHP_EOL);
            exit(1);
        }
        if (!class_exists($className) || !method_exists($className, $methodName)) {
            $skipReasons[] = "missing_method:" . $className . "::" . $methodName;
        }
    }

    if ($skipReasons !== array()) {
        $skippedScenarios[] = array(
            "scenario_id" => $scenarioId,
            "corpus_file" => basename($file),
            "skip_reasons" => array_values(array_unique($skipReasons)),
        );
        continue;
    }

    $replayPlan = array(
        "request_method" => $requestMethod,
        "request_uri" => $endpoint,
    );
    if ($targetParam !== "") {
        $replayPlan["target_query_param"] = $targetParam;
    }
    if ($targetBodyParam !== "") {
        $replayPlan["target_body_param"] = $targetBodyParam;
    }
    if ($targetParamLocation !== "") {
        $replayPlan["target_param_location"] = $targetParamLocation;
    }
    if (is_scalar($payload["replay_body"] ?? null)) {
        $replayPlan["replay_body"] = (string) $payload["replay_body"];
    }
    if (is_array($payload["replay_headers"] ?? null)) {
        $headers = array();
        foreach ($payload["replay_headers"] as $key => $value) {
            if (!is_scalar($value)) {
                continue;
            }
            $normalizedKey = strtolower(trim((string) $key));
            if ($normalizedKey === "") {
                continue;
            }
            $headers[$normalizedKey] = trim((string) $value);
        }
        if ($headers !== array()) {
            ksort($headers);
            $replayPlan["replay_headers"] = $headers;
        }
    }
    if (is_array($payload["replay_cookies"] ?? null)) {
        $cookies = array();
        foreach ($payload["replay_cookies"] as $key => $value) {
            if (!is_scalar($value)) {
                continue;
            }
            $normalizedKey = trim((string) $key);
            if ($normalizedKey === "") {
                continue;
            }
            $cookies[$normalizedKey] = (string) $value;
        }
        if ($cookies !== array()) {
            ksort($cookies);
            $replayPlan["replay_cookies"] = $cookies;
        }
    }
    if (is_array($payload["allowed_methods"] ?? null)) {
        $allowedMethods = array();
        foreach ($payload["allowed_methods"] as $method) {
            if (!is_scalar($method)) {
                continue;
            }
            $normalizedMethod = strtoupper(trim((string) $method));
            if ($normalizedMethod === "") {
                continue;
            }
            $allowedMethods[] = $normalizedMethod;
        }
        if ($allowedMethods !== array()) {
            $replayPlan["allowed_methods"] = array_values(array_unique($allowedMethods));
        }
    }
    foreach (array("idor_resource_param", "idor_actor_param", "idor_mode_param", "idor_owner_actor", "idor_non_owner_actor") as $optionalKey) {
        if (array_key_exists($optionalKey, $plan) && is_scalar($plan[$optionalKey])) {
            $replayPlan[$optionalKey] = (string) $plan[$optionalKey];
        }
    }

    $job = new VerificationJob(
        jobId: hash("sha256", $scenarioId . "|local_corpus|" . $oracleMap[$category]),
        candidateId: $scenarioId,
        sinkCategory: $category,
        oracleType: $oracleMap[$category],
        replayProfile: "local_corpus",
        createdAt: gmdate("c"),
        attemptCount: 0,
        status: "pending",
        candidateSnapshot: array(
            "reason_codes" => array("DETECTOR_TAINT_INPUT"),
            "detector_evidence" => array(
                "finding_count" => 1,
                "detectors" => array("taint-input-detector"),
            ),
            "taint_evidence" => array(
                "has_taint" => true,
            ),
        ),
        replayPlan: $replayPlan,
        metadata: array(
            "scenario_id" => $scenarioId,
            "scenario_kind" => $scenarioKind,
            "expected_confirmed" => $expectedConfirmed,
            "corpus_phase" => $corpusPhase,
            "source" => "local_verifier_corpus",
        )
    );

    $queue->enqueue($job);
    $queuedScenarios++;
}

$requirementsSummary = array(
    "generated_at" => gmdate("c"),
    "runtime_dir" => $runtimeDir,
    "total_scenarios" => $totalScenarios,
    "queued_scenarios" => $queuedScenarios,
    "skipped_scenarios_count" => count($skippedScenarios),
    "skipped_scenarios" => $skippedScenarios,
);

$encodedRequirementsSummary = json_encode($requirementsSummary, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
if (is_string($encodedRequirementsSummary)) {
    file_put_contents($requirementsSummaryPath, $encodedRequirementsSummary . PHP_EOL);
}
' "${ROOT_DIR}/vendor/autoload.php" "${CORPUS_DIR}" "${RUNTIME_DIR}"

PHP_TAINT_TRACE_VERIFIER_RUNTIME_DIR="${RUNTIME_DIR}" \
PHP_TAINT_TRACE_VERIFIER_REPLAY_TARGET=local \
PHP_TAINT_TRACE_VERIFIER_LOCAL_BASE_URL="http://127.0.0.1:${BASE_PORT}" \
PHP_TAINT_TRACE_VERIFIER_CALLBACK_BASE_URL="http://127.0.0.1:${CALLBACK_PORT}" \
PHP_TAINT_TRACE_VERIFIER_BATCH_SIZE=1000 \
php scripts/run_verifier_worker.php

echo "[corpus] verifier runtime dir: ${RUNTIME_DIR}"
echo "[corpus] results: ${RUNTIME_DIR}/results.jsonl"
echo "[corpus] decisions: ${RUNTIME_DIR}/decisions.jsonl"
echo "[corpus] requirements summary: ${RUNTIME_DIR}/scenario_requirements_summary.json"
