<?php

declare(strict_types=1);

namespace PhpTaintTrace\Tests\Parity;

use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;

final class LegacyParityCatalog
{
    /**
     * Baseline filter wrappers in PRVD_OLD/src/filter.
     *
     * @var string[]
     */
    private const FILTER_FUNCTIONS = array(
        'base64_decode',
        'basename',
        'dirname',
        'explode',
        'gzuncompress',
        'hex2bin',
        'html_entity_decode',
        'htmlspecialchars_decode',
        'implode',
        'join',
        'json_decode',
        'ltrim',
        'pathinfo',
        'rawurldecode',
        'rawurlencode',
        'rtrim',
        'sprintf',
        'str_ireplace',
        'str_pad',
        'str_replace',
        'strstr',
        'strtolower',
        'strtoupper',
        'substr',
        'trim',
        'urldecode',
        'urlencode',
        'vsprintf',
    );

    /**
     * Baseline sink tests in PRVD_OLD/tests/sink.
     * Includes one legacy cross-category case: ssrf/file_get_contents.
     *
     * @var array<string, string[]>
     */
    private const SINK_TEST_TARGETS = array(
        'file' => array(
            'copy',
            'dir',
            'file',
            'file_get_contents',
            'file_put_contents',
            'fopen',
            'glob',
            'highlight_file',
            'link',
            'move_uploaded_file',
            'opendir',
            'readfile',
            'rename',
            'rmdir',
            'scandir',
            'show_source',
            'unlink',
        ),
        'rce' => array(
            'exec',
            'passthru',
            'popen',
            'proc_open',
            'shell_exec',
            'system',
            'unserialize',
        ),
        'sqli' => array(
            'mysqli',
            'mysqli_init',
            'mysqli_multi_query',
            'mysqli_prepare',
            'mysqli_query',
            'mysqli_real_query',
            'pdo',
            'pg_prepare',
            'pg_query',
            'pg_query_params',
            'pg_send_prepare',
            'pg_send_query',
            'pg_send_query_params',
            'sqlite3',
        ),
        'ssrf' => array(
            'curl_exec',
            'file_get_contents',
            'fsockopen',
            'get_headers',
        ),
        'xss' => array(
            'print_r',
            'printf',
            'vprintf',
        ),
    );

    /**
     * Baseline opcode handlers in PRVD_OLD/src/opcode.
     *
     * @var string[]
     */
    private const OPCODE_HOOKS = array(
        'assign_concat',
        'concat',
        'do_fcall',
        'do_fcall_by_name',
        'do_icall',
        'do_ucall',
        'echo',
        'exit',
        'fast_concat',
        'include_or_eval',
        'init_dynamic_call',
        'init_method_call',
        'init_user_call',
        'rope_end',
    );

    /**
     * Files ignored for parity mapping because they are test support files.
     *
     * @var string[]
     */
    private const LEGACY_TEST_EXCLUSIONS = array(
        'tests/bootstrap.php',
        'tests/sink/sqli/config.php',
    );

    /**
     * @return string[]
     */
    public static function filterFunctions(): array
    {
        return self::FILTER_FUNCTIONS;
    }

    /**
     * @return array<string, string[]>
     */
    public static function sinkTestTargets(): array
    {
        return self::SINK_TEST_TARGETS;
    }

    /**
     * @return string[]
     */
    public static function opcodeHooks(): array
    {
        return self::OPCODE_HOOKS;
    }

    /**
     * @return array<string, int>
     */
    public static function inventoryCounts(): array
    {
        return array(
            'filters' => count(self::FILTER_FUNCTIONS),
            'opcode_hooks' => count(self::OPCODE_HOOKS),
            'sink_file' => count(self::SINK_TEST_TARGETS['file']),
            'sink_rce' => count(self::SINK_TEST_TARGETS['rce']),
            'sink_sqli' => count(self::SINK_TEST_TARGETS['sqli']),
            'sink_ssrf' => count(self::SINK_TEST_TARGETS['ssrf']),
            'sink_xss' => count(self::SINK_TEST_TARGETS['xss']),
            'sink_total' => array_sum(array_map('count', self::SINK_TEST_TARGETS)),
        );
    }

    /**
     * Contract records describing expected baseline behavior for each legacy test file.
     *
     * @return array<int, array<string, mixed>>
     */
    public static function contracts(): array
    {
        $contracts = array();

        foreach (self::FILTER_FUNCTIONS as $function) {
            $id = sprintf('filter.%s', $function);
            $mode = 'taint_propagation';
            $expectation = array(
                'taint_result_when_tainted_input' => true,
            );
            $notes = array();

            if ($function === 'json_decode') {
                $mode = 'taint_propagation_mixed';
                $expectation = array(
                    'object_decode_taint_result' => false,
                    'assoc_decode_taint_result' => true,
                );
                $notes[] = 'Legacy behavior: object result is not taint-marked, assoc array result is taint-marked.';
            }

            $contracts[] = self::makeContract(
                id: $id,
                domain: 'filter',
                category: 'filter',
                target: $function,
                mode: $mode,
                legacyTestFile: sprintf('tests/filter/001-%s.php', $function),
                expectation: $expectation,
                notes: $notes
            );
        }

        foreach (self::SINK_TEST_TARGETS as $category => $targets) {
            foreach ($targets as $target) {
                $id = sprintf('sink.%s.%s', $category, $target);
                $mode = $category === 'xss' ? 'taint_only' : 'taint_and_payload';
                $expectation = $category === 'xss'
                    ? array('taint_event_when_taint_mode_enabled' => true)
                    : array(
                        'taint_event_when_taint_mode_enabled' => true,
                        'payload_event' => true,
                    );
                $notes = array();

                if ($category === 'ssrf' && $target === 'curl_exec') {
                    $expectation = array(
                        'taint_event_when_taint_mode_enabled' => true,
                        'payload_event' => true,
                    );
                    $notes[] = 'Rewrite enhancement: curl_exec checks tracked URL from curl_init/curl_setopt/curl_setopt_array.';
                }

                if ($category === 'sqli' && $target === 'mysqli_init') {
                    $mode = 'behavior_only';
                    $expectation = array(
                        'returns_instance_of' => 'mysqli',
                    );
                    $notes[] = 'Legacy test validates wrapper object behavior, not sink detection.';
                }

                if ($category === 'ssrf' && $target === 'file_get_contents') {
                    $notes[] = 'Legacy SSRF checks route through file sink wrapper for file_get_contents.';
                }

                $contracts[] = self::makeContract(
                    id: $id,
                    domain: 'sink',
                    category: $category,
                    target: $target,
                    mode: $mode,
                    legacyTestFile: sprintf('tests/sink/%s/001-%s.php', $category, $target),
                    expectation: $expectation,
                    notes: $notes
                );
            }
        }

        foreach (self::OPCODE_HOOKS as $opcode) {
            $id = sprintf('opcode.%s', $opcode);
            $mode = 'taint_propagation';
            $expectation = array(
                'taint_result_when_tainted_input' => true,
            );
            $notes = array();

            if (in_array($opcode, array('do_fcall', 'echo', 'exit'), true)) {
                $mode = 'taint_only';
                $expectation = array(
                    'taint_event_when_taint_mode_enabled' => true,
                );
            } elseif (in_array($opcode, array('do_fcall_by_name', 'do_icall', 'do_ucall', 'include_or_eval', 'init_dynamic_call', 'init_method_call', 'init_user_call'), true)) {
                $mode = 'taint_and_payload';
                $expectation = array(
                    'taint_event_when_taint_mode_enabled' => true,
                    'payload_event' => true,
                );
            }

            $contracts[] = self::makeContract(
                id: $id,
                domain: 'opcode',
                category: 'opcode',
                target: $opcode,
                mode: $mode,
                legacyTestFile: sprintf('tests/opcode/001-%s.php', $opcode),
                expectation: $expectation,
                notes: $notes
            );
        }

        usort($contracts, static fn (array $a, array $b): int => strcmp((string) $a['id'], (string) $b['id']));
        return $contracts;
    }

    /**
     * @return string[]
     */
    public static function legacyTestFiles(): array
    {
        $files = array();

        foreach (self::FILTER_FUNCTIONS as $function) {
            $files[] = sprintf('tests/filter/001-%s.php', $function);
        }

        foreach (self::SINK_TEST_TARGETS as $category => $targets) {
            foreach ($targets as $target) {
                $files[] = sprintf('tests/sink/%s/001-%s.php', $category, $target);
            }
        }

        foreach (self::OPCODE_HOOKS as $opcode) {
            $files[] = sprintf('tests/opcode/001-%s.php', $opcode);
        }

        sort($files);
        return $files;
    }

    /**
     * @return string[]
     */
    public static function discoverLegacyTestFilesFromPrvdOld(): array
    {
        $root = dirname(__DIR__, 2);
        $testsDir = $root . '/PRVD_OLD/tests';
        $results = array();

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($testsDir, FilesystemIterator::SKIP_DOTS)
        );

        foreach ($iterator as $file) {
            if (!$file->isFile()) {
                continue;
            }

            $absolute = str_replace('\\', '/', $file->getPathname());
            $relative = 'tests/' . ltrim(str_replace(str_replace('\\', '/', $testsDir), '', $absolute), '/');

            if (in_array($relative, self::LEGACY_TEST_EXCLUSIONS, true)) {
                continue;
            }

            $results[] = $relative;
        }

        sort($results);
        return $results;
    }

    /**
     * @return array<string, string>
     */
    public static function knownGaps(): array
    {
        return array();
    }

    /**
     * @return array<string, mixed>
     */
    private static function makeContract(
        string $id,
        string $domain,
        string $category,
        string $target,
        string $mode,
        string $legacyTestFile,
        array $expectation,
        array $notes
    ): array {
        return array(
            'id' => $id,
            'domain' => $domain,
            'category' => $category,
            'target' => $target,
            'mode' => $mode,
            'legacy_test_file' => $legacyTestFile,
            'expectation' => $expectation,
            'notes' => $notes,
        );
    }
}
