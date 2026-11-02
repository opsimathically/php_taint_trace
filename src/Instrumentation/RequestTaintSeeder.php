<?php

declare(strict_types=1);

namespace PhpTaintTrace\Instrumentation;

final class RequestTaintSeeder
{
    public function __construct(
        private readonly InstrumentationBackendInterface $backend
    ) {
    }

    /**
     * Mirrors PRVD_OLD bootstrap taint seeding behavior.
     *
     * @param array<string, mixed> $get
     * @param array<string, mixed> $post
     * @param array<string, mixed> $cookie
     * @param array<string, mixed> $files
     * @param array<string, mixed> $request
     * @param array<string, mixed> $server
     * @return string[] Seeded taint source identifiers.
     */
    public function seedSuperglobals(
        array &$get,
        array &$post,
        array &$cookie,
        array &$files,
        array &$request,
        array &$server
    ): array {
        $seededSources = array('_GET', '_POST', '_COOKIE', '_FILES', '_REQUEST');

        $this->backend->markTainted($get, true, '_GET');
        $this->backend->markTainted($post, true, '_POST');
        $this->backend->markTainted($cookie, true, '_COOKIE');
        $this->backend->markTainted($files, true, '_FILES');
        $this->backend->markTainted($request, true, '_REQUEST');

        foreach ($server as $key => &$value) {
            if (str_starts_with((string) $key, 'HTTP_')) {
                $source = sprintf('_SERVER[%s]', (string) $key);
                $this->backend->markTainted($value, true, $source);
                $seededSources[] = $source;
            }
        }
        unset($value);

        return $seededSources;
    }
}
