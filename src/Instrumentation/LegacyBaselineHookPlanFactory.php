<?php

declare(strict_types=1);

namespace PhpTaintTrace\Instrumentation;

final class LegacyBaselineHookPlanFactory
{
    /**
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
     * @var array<string, string[]>
     */
    private const SINK_FUNCTIONS = array(
        'file' => array(
            'chdir',
            'chmod',
            'chown',
            'copy',
            'dir',
            'file',
            'file_get_contents',
            'file_put_contents',
            'fopen',
            'glob',
            'highlight_file',
            'link',
            'mkdir',
            'move_uploaded_file',
            'opendir',
            'readfile',
            'rename',
            'rmdir',
            'scandir',
            'show_source',
            'symlink',
            'touch',
            'unlink',
        ),
        'rce' => array(
            'dl',
            'exec',
            'expect_popen',
            'mail',
            'passthru',
            'pcntl_exec',
            'popen',
            'proc_open',
            'shell_exec',
            'system',
            'unserialize',
        ),
        'sqli' => array(
            'mysqli_execute_query',
            'mysqli_init',
            'mysqli_multi_query',
            'mysqli_query',
            'mysqli_prepare',
            'mysqli_real_query',
            'pg_prepare',
            'pg_query',
            'pg_query_prepared',
            'pg_query_params',
            'pg_send_execute',
            'pg_send_prepare',
            'pg_send_query',
            'pg_send_query_params',
            'pg_execute',
            'oci_execute',
            'oci_parse',
            'sqlsrv_prepare',
            'sqlsrv_query',
        ),
        'ssrf' => array(
            'curl_exec',
            'curl_multi_exec',
            'fsockopen',
            'get_headers',
            'pfsockopen',
            'stream_socket_client',
        ),
        'xxe' => array(
            'simplexml_load_file',
            'simplexml_load_string',
        ),
        'xss' => array(
            'print_r',
            'printf',
            'vprintf',
        ),
    );

    /**
     * @var array<string, string[]>
     */
    private const SINK_METHODS = array(
        'file' => array(
            'SplFileObject' => array('__construct'),
        ),
        'sqli' => array(
            'mysqli' => array('query', 'prepare', 'real_query', 'multi_query', 'execute_query'),
            'PDO' => array('query', 'prepare', 'exec'),
            'SQLite3' => array('exec', 'query', 'prepare', 'querySingle'),
        ),
        'ssrf' => array(
            'SoapClient' => array('__construct', '__setLocation'),
        ),
        'xxe' => array(
            'DOMDocument' => array('load', 'loadXML'),
            'XMLReader' => array('open', 'XML'),
        ),
    );

    /**
     * @var array<string, HookPhase>
     */
    private const OPCODES = array(
        'assign_concat' => HookPhase::AFTER,
        'concat' => HookPhase::AFTER,
        'do_fcall' => HookPhase::BEFORE,
        'do_fcall_by_name' => HookPhase::BEFORE,
        'do_icall' => HookPhase::BEFORE,
        'do_ucall' => HookPhase::BEFORE,
        'echo' => HookPhase::BEFORE,
        'exit' => HookPhase::BEFORE,
        'fast_concat' => HookPhase::AFTER,
        'include_or_eval' => HookPhase::BEFORE,
        'init_dynamic_call' => HookPhase::BEFORE,
        'init_method_call' => HookPhase::BEFORE,
        'init_user_call' => HookPhase::BEFORE,
        'rope_end' => HookPhase::AFTER,
    );

    public static function create(): BaselineHookPlan
    {
        $hooks = array();

        foreach (self::FILTER_FUNCTIONS as $functionName) {
            $hooks[] = HookDefinition::function(
                id: sprintf('filter.%s', $functionName),
                functionName: $functionName,
                phase: HookPhase::REPLACE,
                metadata: array(
                    'domain' => 'filter',
                    'category' => 'filter',
                    'legacy_test_file' => sprintf('tests/filter/001-%s.php', $functionName),
                )
            );
        }

        foreach (self::SINK_FUNCTIONS as $category => $functionNames) {
            foreach ($functionNames as $functionName) {
                $hooks[] = HookDefinition::function(
                    id: sprintf('sink.%s.%s', $category, $functionName),
                    functionName: $functionName,
                    phase: HookPhase::REPLACE,
                    metadata: array(
                        'domain' => 'sink',
                        'category' => $category,
                        'legacy_test_file' => sprintf('tests/sink/%s/001-%s.php', $category, $functionName),
                    )
                );
            }
        }

        // Legacy SSRF behavior includes file_get_contents through the file sink wrapper path.
        $hooks[] = HookDefinition::function(
            id: 'sink.ssrf.file_get_contents',
            functionName: 'file_get_contents',
            phase: HookPhase::REPLACE,
            metadata: array(
                'domain' => 'sink',
                'category' => 'ssrf',
                'legacy_test_file' => 'tests/sink/ssrf/001-file_get_contents.php',
                'legacy_shared_path' => true,
            )
        );

        foreach (self::SINK_METHODS as $category => $classes) {
            foreach ($classes as $className => $methods) {
                foreach ($methods as $methodName) {
                    $hooks[] = HookDefinition::method(
                        id: sprintf('method.%s.%s.%s', $category, strtolower($className), $methodName),
                        className: $className,
                        methodName: $methodName,
                        phase: HookPhase::REPLACE,
                        metadata: array(
                            'domain' => 'sink',
                            'category' => $category,
                            'api_type' => 'method',
                        )
                    );
                }
            }
        }

        foreach (self::OPCODES as $opcodeName => $phase) {
            $hooks[] = HookDefinition::opcode(
                id: sprintf('opcode.%s', $opcodeName),
                opcode: sprintf('XMARK_%s', strtoupper($opcodeName)),
                phase: $phase,
                metadata: array(
                    'domain' => 'opcode',
                    'category' => 'opcode',
                    'legacy_test_file' => sprintf('tests/opcode/001-%s.php', $opcodeName),
                )
            );
        }

        return new BaselineHookPlan(...$hooks);
    }
}
