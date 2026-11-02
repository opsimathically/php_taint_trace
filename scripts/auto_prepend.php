<?php

declare(strict_types=1);

$rootDir = dirname(__DIR__);
$autoloadPath = $rootDir . '/vendor/autoload.php';
if (!is_file($autoloadPath)) {
    error_log('[php_taint_trace] Missing Composer autoload at ' . $autoloadPath);
    return;
}

require $autoloadPath;

try {
    $bootstrap = \PhpTaintTrace\Runtime\AppRuntimeBootstrap::createFromEnvironment();
    if (!$bootstrap->config()->enabled()) {
        return;
    }

    $bootstrap->bootstrapCurrentRequest();
    $bootstrap->registerShutdownHandler();
} catch (\Throwable $error) {
    error_log('[php_taint_trace] bootstrap failure: ' . $error->getMessage());
}
