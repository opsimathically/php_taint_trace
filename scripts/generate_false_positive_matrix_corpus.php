#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * Generate adversarial false-positive matrix corpus scenarios.
 *
 * Usage:
 *   php scripts/generate_false_positive_matrix_corpus.php --corpus-dir /path/to/corpus
 */

$corpusDir = null;
for ($i = 1; $i < $argc; $i++) {
    $arg = $argv[$i];
    if ($arg === '--corpus-dir' && isset($argv[$i + 1])) {
        $corpusDir = $argv[++$i];
        continue;
    }
}

if (!is_string($corpusDir) || trim($corpusDir) === '') {
    fwrite(STDERR, "[fp-matrix] missing required --corpus-dir argument" . PHP_EOL);
    exit(1);
}

$safeEndpointByCategory = array(
    'rce' => '/rce_fp_allowlist_alias',
    'ssrf' => '/ssrf_fp_metadata_probe',
    'sqli' => '/sqli_fp_token_filter_safe',
    'file' => '/file_fp_guarded_safe',
    'xss' => '/xss_fp_strip_tags_safe',
    'idor' => '/idor_fp_strict_safe',
);

$vulnerableEndpointByCategory = array(
    'rce' => '/rce_tricky_decode_after_check',
    'ssrf' => '/ssrf_tricky_dns_guarded_confirmed',
    'sqli' => '/sqli_tricky_cast_then_fallback',
    'file' => '/file_tricky_basename_confirmed',
    'xss' => '/xss_tricky_encode_decode_confirmed',
    'idor' => '/idor_tricky_token_bypass_confirmed',
);

$targetParamByCategory = array(
    'rce' => 'cmd',
    'ssrf' => 'url',
    'sqli' => 'q',
    'file' => 'path',
    'xss' => 'name',
    'idor' => 'resource_id',
);

$initialValueByCategory = array(
    'rce' => 'echo xtanzi',
    'ssrf' => 'http://127.0.0.1:18081/?name=xtanzi',
    'sqli' => '1',
    'file' => '/etc/hostname',
    'xss' => '<script>xtanzi</script>',
    'idor' => '42',
);

$confirmedReasonByCategory = array(
    'rce' => 'VERIFIER_RCE_NONCE_CONFIRMED',
    'ssrf' => 'VERIFIER_SSRF_CALLBACK_CONFIRMED',
    'sqli' => 'VERIFIER_SQLI_UNION_CONFIRMED',
    'file' => 'VERIFIER_FILE_DIFFERENTIAL_CONFIRMED',
    'xss' => 'VERIFIER_XSS_CONTEXT_CONFIRMED',
    'idor' => 'VERIFIER_IDOR_DIFFERENTIAL_CONFIRMED',
);

$valueVariants = array(
    'plain' => static fn (string $value): string => $value,
    'encoded_once' => static fn (string $value): string => rawurlencode($value),
);

$scenarioCount = 0;
foreach ($safeEndpointByCategory as $category => $safeEndpoint) {
    $targetParam = $targetParamByCategory[$category];
    $baseValue = $initialValueByCategory[$category];
    $vulnerableEndpoint = $vulnerableEndpointByCategory[$category];
    $confirmedReason = $confirmedReasonByCategory[$category];

    foreach (array('safe', 'vulnerable') as $scenarioKind) {
        $isSafe = $scenarioKind === 'safe';
        $endpointBase = $isSafe ? $safeEndpoint : $vulnerableEndpoint;
        $expectedConfirmed = !$isSafe;
        $expectedOutcome = $isSafe ? 'not_confirmed' : 'confirmed';
        $expectedTier = $isSafe ? 'invalid' : 'confirmed';

        foreach ($valueVariants as $variantLabel => $variantFactory) {
            $value = $variantFactory($baseValue);

            // Query/GET shape.
            $queryParams = array($targetParam => $value, 'shape' => 'query_get', 'variant' => $variantLabel);
            if ($category === 'idor') {
                $queryParams['actor_id'] = '1043';
                $queryParams['mode'] = 'vuln';
                $queryParams['authz_token'] = '';
            }
            $endpoint = $endpointBase . '?' . http_build_query($queryParams);
            $scenarioId = sprintf('fpm_%s_%s_query_get_%s', $category, $scenarioKind, $variantLabel);
            $scenario = array(
                'scenario_id' => $scenarioId,
                'corpus_phase' => 'false_positive_matrix_v1',
                'category' => $category,
                'scenario_kind' => $scenarioKind,
                'request_shape' => 'query_get',
                'expected_confirmed' => $expectedConfirmed,
                'expected_outcome' => $expectedOutcome,
                'expected_decision_tier' => $expectedTier,
                'endpoint' => $endpoint,
                'payload_plan' => array(
                    'target_query_param' => $targetParam,
                    'target_param_location' => 'query',
                ),
            );
            if (!$isSafe) {
                $scenario['expected_reason_codes_any'] = array($confirmedReason);
            }
            if ($category === 'idor') {
                $scenario['payload_plan']['idor_resource_param'] = 'resource_id';
                $scenario['payload_plan']['idor_actor_param'] = 'actor_id';
                $scenario['payload_plan']['idor_mode_param'] = 'mode';
            }
            file_put_contents(
                $corpusDir . '/' . $scenarioId . '.json',
                json_encode($scenario, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL
            );
            $scenarioCount++;

            // Query/POST shape with policy override.
            $queryParams = array($targetParam => $value, 'shape' => 'query_post', 'variant' => $variantLabel);
            if ($category === 'idor') {
                $queryParams['actor_id'] = '1043';
                $queryParams['mode'] = 'vuln';
                $queryParams['authz_token'] = '';
            }
            $endpoint = $endpointBase . '?' . http_build_query($queryParams);
            $scenarioId = sprintf('fpm_%s_%s_query_post_%s', $category, $scenarioKind, $variantLabel);
            $scenario = array(
                'scenario_id' => $scenarioId,
                'corpus_phase' => 'false_positive_matrix_v1',
                'category' => $category,
                'scenario_kind' => $scenarioKind,
                'request_shape' => 'query_post',
                'request_method' => 'POST',
                'allowed_methods' => array('POST'),
                'expected_confirmed' => $expectedConfirmed,
                'expected_outcome' => $expectedOutcome,
                'expected_decision_tier' => $expectedTier,
                'endpoint' => $endpoint,
                'payload_plan' => array(
                    'target_query_param' => $targetParam,
                    'target_param_location' => 'query',
                ),
            );
            if (!$isSafe) {
                $scenario['expected_reason_codes_any'] = array($confirmedReason);
            }
            if ($category === 'idor') {
                $scenario['payload_plan']['idor_resource_param'] = 'resource_id';
                $scenario['payload_plan']['idor_actor_param'] = 'actor_id';
                $scenario['payload_plan']['idor_mode_param'] = 'mode';
            }
            file_put_contents(
                $corpusDir . '/' . $scenarioId . '.json',
                json_encode($scenario, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL
            );
            $scenarioCount++;

            // Body/POST shape for non-IDOR categories.
            if ($category !== 'idor') {
                $bodyParams = array($targetParam => $value, 'shape' => 'body_post', 'variant' => $variantLabel);
                $scenarioId = sprintf('fpm_%s_%s_body_post_%s', $category, $scenarioKind, $variantLabel);
                $scenario = array(
                    'scenario_id' => $scenarioId,
                    'corpus_phase' => 'false_positive_matrix_v1',
                    'category' => $category,
                    'scenario_kind' => $scenarioKind,
                    'request_shape' => 'body_post',
                    'request_method' => 'POST',
                    'allowed_methods' => array('POST'),
                    'expected_confirmed' => $expectedConfirmed,
                    'expected_outcome' => $expectedOutcome,
                    'expected_decision_tier' => $expectedTier,
                    'endpoint' => $endpointBase,
                    'replay_body' => http_build_query($bodyParams),
                    'payload_plan' => array(
                        'target_body_param' => $targetParam,
                        'target_param_location' => 'body',
                    ),
                );
                if (!$isSafe) {
                    $scenario['expected_reason_codes_any'] = array($confirmedReason);
                }
                file_put_contents(
                    $corpusDir . '/' . $scenarioId . '.json',
                    json_encode($scenario, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL
                );
                $scenarioCount++;
            }
        }
    }
}

fwrite(STDOUT, sprintf("[fp-matrix] generated scenarios=%d%s", $scenarioCount, PHP_EOL));
