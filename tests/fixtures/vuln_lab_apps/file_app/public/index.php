<?php

declare(strict_types=1);

$path = (string) ($_GET['path'] ?? '/etc/hostname');
$sink = strtolower(trim((string) ($_GET['sink'] ?? 'file_get_contents')));

if ($sink === 'splfileobject') {
    try {
        $file = new SplFileObject($path, 'r');
        $line = $file->fgets();
        if (!is_string($line) || trim($line) === '') {
            http_response_code(500);
            echo "read failed";
            return;
        }
    } catch (Throwable) {
        http_response_code(500);
        echo "read failed";
        return;
    }

    echo trim($line) . "\n";
    return;
}

if ($sink === 'fopen') {
    $handle = @fopen($path, 'r');
    if (!is_resource($handle)) {
        http_response_code(500);
        echo "read failed";
        return;
    }

    $contents = stream_get_contents($handle);
    fclose($handle);
    if (!is_string($contents) || trim($contents) === '') {
        http_response_code(500);
        echo "read failed";
        return;
    }

    echo $contents;
    return;
}

if ($sink === 'readfile') {
    ob_start();
    $bytes = @readfile($path);
    $contents = ob_get_clean();
    if (!is_int($bytes) || $bytes <= 0 || !is_string($contents) || trim($contents) === '') {
        http_response_code(500);
        echo "read failed";
        return;
    }

    echo $contents;
    return;
}

$contents = @file_get_contents($path);
if ($contents === false) {
    http_response_code(500);
    echo "read failed";
    return;
}

echo $contents;
