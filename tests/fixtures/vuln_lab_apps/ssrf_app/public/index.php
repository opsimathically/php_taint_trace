<?php

declare(strict_types=1);

/**
 * @return array{host: string, port: int, path: string}|null
 */
function parseHttpTarget(string $url): ?array
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

function fetchViaStreamSocketClient(string $url): string|false
{
    $target = parseHttpTarget($url);
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

function fetchViaPfsockopen(string $url): string|false
{
    $target = parseHttpTarget($url);
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

function fetchViaFsockopen(string $url): string|false
{
    $target = parseHttpTarget($url);
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

function fetchViaCurl(string $url, string $mode = 'setopt'): string|false
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
    @curl_close($handle);

    return is_string($body) ? $body : false;
}

function fetchViaCurlMulti(string $url, string $mode = 'setopt'): string|false
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

$sink = strtolower(trim((string) ($_GET['sink'] ?? 'file_get_contents')));
$url = (string) ($_GET['url'] ?? 'http://127.0.0.1:9/');

if ($sink === 'stream_socket_client') {
    // Intentionally pass the raw user-controlled target as the sink argument.
    $socket = @stream_socket_client($url, $errno, $errstr, 0.5);
    if (is_resource($socket)) {
        fclose($socket);
    }
    echo 'stream socket attempted';
    return;
}

if ($sink === 'pfsockopen') {
    // Intentionally pass the raw user-controlled target as the sink argument.
    $socket = @pfsockopen($url, 80, $errno, $errstr, 0.5);
    if (is_resource($socket)) {
        fclose($socket);
    }
    echo 'persistent socket attempted';
    return;
}

if ($sink === 'fsockopen') {
    // Intentionally pass the raw user-controlled target as the sink argument.
    $socket = @fsockopen($url, 80, $errno, $errstr, 0.5);
    if (is_resource($socket)) {
        fclose($socket);
    }

    $body = fetchViaFsockopen($url);
    if (!is_string($body) || $body === '') {
        http_response_code(502);
        echo 'fetch failed';
        return;
    }

    echo $body;
    return;
}

if ($sink === 'get_headers') {
    // Intentionally pass the raw user-controlled URL into get_headers sink.
    $headers = @get_headers($url, true);
    if (!is_array($headers) || $headers === array()) {
        http_response_code(502);
        echo 'fetch failed';
        return;
    }

    $serialized = array();
    foreach ($headers as $name => $value) {
        if (is_array($value)) {
            $serialized[] = sprintf('%s: %s', (string) $name, implode(', ', array_map(static fn (mixed $item): string => (string) $item, $value)));
            continue;
        }

        $serialized[] = sprintf('%s: %s', (string) $name, (string) $value);
    }

    echo implode("\n", $serialized);
    return;
}

if ($sink === 'curl_setopt') {
    $body = fetchViaCurl($url, 'setopt');
    if (!is_string($body) || $body === '') {
        http_response_code(502);
        echo "fetch failed";
        return;
    }

    echo $body;
    return;
}

if ($sink === 'curl_setopt_array') {
    $body = fetchViaCurl($url, 'setopt_array');
    if (!is_string($body) || $body === '') {
        http_response_code(502);
        echo "fetch failed";
        return;
    }

    echo $body;
    return;
}

if ($sink === 'curl_multi_setopt') {
    $body = fetchViaCurlMulti($url, 'setopt');
    if (!is_string($body) || $body === '') {
        http_response_code(502);
        echo "fetch failed";
        return;
    }

    echo $body;
    return;
}

if ($sink === 'curl_multi_setopt_array') {
    $body = fetchViaCurlMulti($url, 'setopt_array');
    if (!is_string($body) || $body === '') {
        http_response_code(502);
        echo "fetch failed";
        return;
    }

    echo $body;
    return;
}

if ($sink === 'soapclient_construct') {
    if (!class_exists('SoapClient')) {
        echo 'extension_unavailable:soap';
        return;
    }

    try {
        // Intentionally pass tainted URL as WSDL argument to exercise SoapClient::__construct sink.
        @new SoapClient($url, array(
            'cache_wsdl' => defined('WSDL_CACHE_NONE') ? WSDL_CACHE_NONE : 0,
            'connection_timeout' => 1,
            'exceptions' => true,
            'trace' => false,
        ));
    } catch (Throwable) {
    }

    echo 'soapclient constructor attempted';
    return;
}

if ($sink === 'soapclient_location') {
    if (!class_exists('SoapClient')) {
        echo 'extension_unavailable:soap';
        return;
    }

    try {
        // Intentionally pass tainted URL as non-WSDL location option to exercise SoapClient::__construct sink.
        @new SoapClient(null, array(
            'location' => $url,
            'uri' => 'urn:ptt:remote',
            'connection_timeout' => 1,
            'exceptions' => true,
            'trace' => false,
        ));
    } catch (Throwable) {
    }

    echo 'soapclient location attempted';
    return;
}

if ($sink === 'soapclient_setlocation') {
    if (!class_exists('SoapClient')) {
        echo 'extension_unavailable:soap';
        return;
    }

    try {
        // Intentionally pass tainted URL into SoapClient::__setLocation to exercise method sink coverage.
        $client = @new SoapClient(null, array(
            'location' => 'http://127.0.0.1:9/',
            'uri' => 'urn:ptt:remote',
            'connection_timeout' => 1,
            'exceptions' => true,
            'trace' => false,
        ));
        if ($client instanceof SoapClient) {
            @$client->__setLocation($url);
            @$client->__soapCall('ping', array());
        }
    } catch (Throwable) {
    }

    echo 'soapclient setlocation attempted';
    return;
}

$body = @file_get_contents($url);
if ($body === false) {
    http_response_code(502);
    echo "fetch failed";
    return;
}

echo $body;
