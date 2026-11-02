<?php

declare(strict_types=1);

/**
 * Intentionally vulnerable SQLi fixture:
 * - MySQL-backed direct execution of user-controlled SQL (`q`) via PDO::query.
 * - Additional raw execution method variants (`PDO::exec`, `SQLite3::query`, `SQLite3::exec`, `SQLite3::querySingle`).
 * - Keeps a deterministic default query for health checks.
 */
$host = (string) ($_ENV['PHP_TAINT_TRACE_LAB_DB_HOST'] ?? getenv('PHP_TAINT_TRACE_LAB_DB_HOST') ?: 'localhost');
$port = (int) ($_ENV['PHP_TAINT_TRACE_LAB_DB_PORT'] ?? getenv('PHP_TAINT_TRACE_LAB_DB_PORT') ?: '3306');
$name = (string) ($_ENV['PHP_TAINT_TRACE_LAB_DB_NAME'] ?? getenv('PHP_TAINT_TRACE_LAB_DB_NAME') ?: 'php_taint_lab');
$user = (string) ($_ENV['PHP_TAINT_TRACE_LAB_DB_USER'] ?? getenv('PHP_TAINT_TRACE_LAB_DB_USER') ?: 'php_taint');
$password = (string) ($_ENV['PHP_TAINT_TRACE_LAB_DB_PASSWORD'] ?? getenv('PHP_TAINT_TRACE_LAB_DB_PASSWORD') ?: 'php_taint_password');
$socket = (string) ($_ENV['PHP_TAINT_TRACE_LAB_DB_SOCKET'] ?? getenv('PHP_TAINT_TRACE_LAB_DB_SOCKET') ?: '/run/mysqld/mysqld.sock');

$q = (string) ($_GET['q'] ?? 'SELECT username FROM users WHERE id = 1');
$sink = strtolower(trim((string) ($_GET['sink'] ?? 'pdo_query')));

if ($sink === 'pg_prepare' || $sink === 'pg_query_prepared') {
    if (!function_exists('pg_prepare')) {
        echo 'extension_unavailable:pg_prepare';
        return;
    }

    $conn = @pg_connect('host=127.0.0.1 port=1 dbname=postgres connect_timeout=1');
    try {
        // Intentionally routes tainted request payload to pg_prepare SQL argument (arg 2).
        @pg_prepare($conn ?: null, 'ptt_stmt', $q);
    } catch (Throwable) {
    }

    echo 'sink_invoked:pg_prepare';
    return;
}

if ($sink === 'pg_execute') {
    if (!function_exists('pg_execute')) {
        echo 'extension_unavailable:pg_execute';
        return;
    }

    $conn = @pg_connect('host=127.0.0.1 port=1 dbname=postgres connect_timeout=1');
    try {
        // Intentionally routes tainted request payload to pg_execute arg 2.
        @pg_execute($conn ?: null, 'ptt_stmt', $q);
    } catch (Throwable) {
    }

    echo 'sink_invoked:pg_execute';
    return;
}

if ($sink === 'pg_send_execute') {
    if (!function_exists('pg_send_execute')) {
        echo 'extension_unavailable:pg_send_execute';
        return;
    }

    $conn = @pg_connect('host=127.0.0.1 port=1 dbname=postgres connect_timeout=1');
    try {
        // Intentionally routes tainted request payload to pg_send_execute arg 2.
        @pg_send_execute($conn ?: null, 'ptt_stmt', $q);
    } catch (Throwable) {
    }

    echo 'sink_invoked:pg_send_execute';
    return;
}

if ($sink === 'sqlsrv_query') {
    if (!function_exists('sqlsrv_query')) {
        echo 'extension_unavailable:sqlsrv_query';
        return;
    }

    $conn = null;
    if (function_exists('sqlsrv_connect')) {
        $conn = @sqlsrv_connect('127.0.0.1', array(
            'UID' => 'php_taint',
            'PWD' => 'php_taint_password',
            'LoginTimeout' => 1,
            'CharacterSet' => 'UTF-8',
        ));
    }

    try {
        @sqlsrv_query($conn, $q);
    } catch (Throwable) {
    }

    echo 'sink_invoked:sqlsrv_query';
    return;
}

if ($sink === 'sqlsrv_prepare') {
    if (!function_exists('sqlsrv_prepare')) {
        echo 'extension_unavailable:sqlsrv_prepare';
        return;
    }

    $conn = null;
    if (function_exists('sqlsrv_connect')) {
        $conn = @sqlsrv_connect('127.0.0.1', array(
            'UID' => 'php_taint',
            'PWD' => 'php_taint_password',
            'LoginTimeout' => 1,
            'CharacterSet' => 'UTF-8',
        ));
    }

    try {
        @sqlsrv_prepare($conn, $q);
    } catch (Throwable) {
    }

    echo 'sink_invoked:sqlsrv_prepare';
    return;
}

if ($sink === 'oci_parse') {
    if (!function_exists('oci_parse')) {
        echo 'extension_unavailable:oci_parse';
        return;
    }

    $conn = null;
    if (function_exists('oci_connect')) {
        $conn = @oci_connect('php_taint', 'php_taint_password', '//127.0.0.1:1521/XE');
    }

    try {
        @oci_parse($conn ?: null, $q);
    } catch (Throwable) {
    }

    echo 'sink_invoked:oci_parse';
    return;
}

if ($sink === 'mysqli_execute_query') {
    if (!function_exists('mysqli_execute_query') || !function_exists('mysqli_init')) {
        echo 'extension_unavailable:mysqli_execute_query';
        return;
    }

    $conn = @mysqli_init();
    if (function_exists('mysqli_report') && defined('MYSQLI_REPORT_OFF')) {
        @mysqli_report(MYSQLI_REPORT_OFF);
    }

    try {
        if ($conn instanceof mysqli) {
            @mysqli_options($conn, MYSQLI_OPT_CONNECT_TIMEOUT, 1);
            @mysqli_real_connect($conn, '127.0.0.1', 'php_taint', 'php_taint_password', 'php_taint_lab', 3306);
            @mysqli_execute_query($conn, $q);
        }
    } catch (Throwable) {
    } finally {
        if ($conn instanceof mysqli) {
            @mysqli_close($conn);
        }
    }

    echo 'sink_invoked:mysqli_execute_query';
    return;
}

if ($sink === 'sqlite3_querysingle') {
    if (!class_exists('SQLite3')) {
        echo 'extension_unavailable:sqlite3';
        return;
    }

    try {
        $db = new SQLite3(':memory:');
        $value = @$db->querySingle($q);
        if ($db instanceof SQLite3) {
            @$db->close();
        }
    } catch (Throwable) {
        echo 'sink_invoked:sqlite3_querysingle';
        return;
    }

    if (is_scalar($value)) {
        echo (string) $value;
        return;
    }

    echo 'sink_invoked:sqlite3_querysingle';
    return;
}

if ($sink === 'sqlite3_query') {
    if (!class_exists('SQLite3')) {
        echo 'extension_unavailable:sqlite3';
        return;
    }

    try {
        $db = new SQLite3(':memory:');
        $result = @$db->query($q);
        if ($result instanceof SQLite3Result) {
            @$result->finalize();
        }
        if ($db instanceof SQLite3) {
            @$db->close();
        }
    } catch (Throwable) {
        echo 'sink_invoked:sqlite3_query';
        return;
    }

    echo 'sink_invoked:sqlite3_query';
    return;
}

if ($sink === 'sqlite3_exec') {
    if (!class_exists('SQLite3')) {
        echo 'extension_unavailable:sqlite3';
        return;
    }

    try {
        $db = new SQLite3(':memory:');
        @$db->exec($q);
        if ($db instanceof SQLite3) {
            @$db->close();
        }
    } catch (Throwable) {
        echo 'sink_invoked:sqlite3_exec';
        return;
    }

    echo 'sink_invoked:sqlite3_exec';
    return;
}

if ($sink === 'pdo_exec') {
    if (!class_exists('PDO')) {
        echo 'extension_unavailable:pdo';
        return;
    }

    try {
        $pdo = new PDO('sqlite::memory:');
        @$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_SILENT);
        @$pdo->exec($q);
    } catch (Throwable) {
        echo 'sink_invoked:pdo_exec';
        return;
    }

    echo 'sink_invoked:pdo_exec';
    return;
}

if (!class_exists('PDO')) {
    http_response_code(500);
    echo 'pdo extension unavailable';
    return;
}

try {
    $dsn = sprintf(
        'mysql:host=%s;port=%d;dbname=%s;unix_socket=%s;charset=utf8mb4',
        $host,
        $port,
        $name,
        $socket
    );
    $db = new PDO($dsn, $user, $password, array(
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_TIMEOUT => 2,
    ));
} catch (Throwable $error) {
    error_log('sqli_app db connect failed: ' . $error->getMessage());
    http_response_code(500);
    echo 'db connect failed';
    return;
}

$sql = $q;
try {
    $result = $db->query($sql);
    if ($result === false) {
        http_response_code(500);
        echo 'query failed';
        return;
    }

    $rows = $result->fetchAll(PDO::FETCH_COLUMN);
    if (!is_array($rows) || $rows === array()) {
        echo 'no rows';
        return;
    }
} catch (Throwable $error) {
    http_response_code(500);
    echo 'query failed';
    return;
}

echo implode(',', array_map(static fn (mixed $value): string => (string) $value, $rows));
