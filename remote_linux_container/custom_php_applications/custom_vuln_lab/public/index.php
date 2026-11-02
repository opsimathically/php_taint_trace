<?php

declare(strict_types=1);

session_start();

require __DIR__ . '/config.php';

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
$path = is_string($path) ? $path : '/';
$method = strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));

if ($path === '/catalog.json') {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(
        array(
            'app' => 'custom_vuln_lab',
            'version' => CUSTOM_VULN_LAB_VERSION,
            'warning' => app_config()['warning'],
            'generated_at_utc' => gmdate(DATE_ATOM),
            'entries' => catalog_entries(),
        ),
        JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
    );
    exit;
}

$handlers = array(
    '/' => 'route_home',
    '/catalog' => 'route_catalog',
    '/xss/reflected' => 'route_xss_reflected',
    '/xss/attr' => 'route_xss_attr',
    '/xss/js' => 'route_xss_js',
    '/xss/stored' => 'route_xss_stored',
    '/xss/filtered' => 'route_xss_filtered',
    '/sqli/error' => 'route_sqli_error',
    '/sqli/union' => 'route_sqli_union',
    '/sqli/blind-bool' => 'route_sqli_blind_bool',
    '/sqli/blind-time' => 'route_sqli_blind_time',
    '/sqli/constrained' => 'route_sqli_constrained',
    '/sqli/login' => 'route_sqli_login',
    '/auth/login' => 'route_auth_login',
    '/auth/logout' => 'route_auth_logout',
    '/csrf/change-email' => 'route_csrf_change_email',
    '/csrf/transfer' => 'route_csrf_transfer',
    '/csrf/weak-token' => 'route_csrf_weak_token',
    '/rce/system' => 'route_rce_system',
    '/rce/filtered' => 'route_rce_filtered',
    '/rce/eval' => 'route_rce_eval',
    '/json/rce/system' => 'route_json_rce_system',
    '/api/json/rce/system' => 'route_api_json_rce_system',
    '/auto/rce/system' => 'route_auto_rce_system',
    '/auto/rce/argv-array' => 'route_auto_rce_argv_array',
    '/api/json/rce/argv-array' => 'route_api_json_rce_argv_array',
    '/auto/rce/workflow-step' => 'route_auto_rce_workflow_step',
    '/api/json/rce/workflow-step' => 'route_api_json_rce_workflow_step',
    '/auto/rce/template-eval' => 'route_auto_rce_template_eval',
    '/api/json/rce/template-eval' => 'route_api_json_rce_template_eval',
    '/auto/rce/env-chain' => 'route_auto_rce_env_chain',
    '/api/json/rce/env-chain' => 'route_api_json_rce_env_chain',
    '/auto/rce/header-command' => 'route_auto_rce_header_command',
    '/api/json/rce/header-command' => 'route_api_json_rce_header_command',
    '/auto/rce/task-matrix' => 'route_auto_rce_task_matrix',
    '/api/json/rce/task-matrix' => 'route_api_json_rce_task_matrix',
    '/ssrf/fetch' => 'route_ssrf_fetch',
    '/ssrf/weak-filter' => 'route_ssrf_weak_filter',
    '/ssrf/redirect' => 'route_ssrf_redirect',
    '/auto/ssrf/fetch' => 'route_auto_ssrf_fetch',
    '/api/json/ssrf/fetch' => 'route_api_json_ssrf_fetch',
    '/auto/ssrf/webhook-basic' => 'route_auto_ssrf_webhook_basic',
    '/api/json/ssrf/webhook-basic' => 'route_api_json_ssrf_webhook_basic',
    '/auto/ssrf/events-callback' => 'route_auto_ssrf_events_callback',
    '/api/json/ssrf/events-callback' => 'route_api_json_ssrf_events_callback',
    '/auto/ssrf/oembed-url' => 'route_auto_ssrf_oembed_url',
    '/api/json/ssrf/oembed-url' => 'route_api_json_ssrf_oembed_url',
    '/auto/ssrf/openapi-server' => 'route_auto_ssrf_openapi_server',
    '/api/json/ssrf/openapi-server' => 'route_api_json_ssrf_openapi_server',
    '/auto/ssrf/avatar-proxy' => 'route_auto_ssrf_avatar_proxy',
    '/api/json/ssrf/avatar-proxy' => 'route_api_json_ssrf_avatar_proxy',
    '/auto/ssrf/rss-feed' => 'route_auto_ssrf_rss_feed',
    '/api/json/ssrf/rss-feed' => 'route_api_json_ssrf_rss_feed',
    '/auto/ssrf/proxy-chain' => 'route_auto_ssrf_proxy_chain',
    '/api/json/ssrf/proxy-chain' => 'route_api_json_ssrf_proxy_chain',
    '/auto/ssrf/cloud-metadata' => 'route_auto_ssrf_cloud_metadata',
    '/api/json/ssrf/cloud-metadata' => 'route_api_json_ssrf_cloud_metadata',
    '/file/lfi' => 'route_file_lfi',
    '/file/lfi-constrained' => 'route_file_lfi_constrained',
    '/file/rfi' => 'route_file_rfi',
    '/json/file/lfi' => 'route_json_file_lfi',
    '/api/json/file/lfi' => 'route_api_json_file_lfi',
    '/auto/file/lfi' => 'route_auto_file_lfi',
    '/auto/file/lang-include' => 'route_auto_file_lang_include',
    '/api/json/file/lang-include' => 'route_api_json_file_lang_include',
    '/auto/file/path-parts' => 'route_auto_file_path_parts',
    '/api/json/file/path-parts' => 'route_api_json_file_path_parts',
    '/auto/file/write-json' => 'route_auto_file_write_json',
    '/api/json/file/write-json' => 'route_api_json_file_write_json',
    '/auto/file/base64-read' => 'route_auto_file_base64_read',
    '/api/json/file/base64-read' => 'route_api_json_file_base64_read',
    '/auto/file/theme-asset' => 'route_auto_file_theme_asset',
    '/api/json/file/theme-asset' => 'route_api_json_file_theme_asset',
    '/auto/file/temp-cleanup' => 'route_auto_file_temp_cleanup',
    '/api/json/file/temp-cleanup' => 'route_api_json_file_temp_cleanup',
    '/auto/file/archive-extract' => 'route_auto_file_archive_extract',
    '/api/json/file/archive-extract' => 'route_api_json_file_archive_extract',
    '/auto/file/log-read' => 'route_auto_file_log_read',
    '/api/json/file/log-read' => 'route_api_json_file_log_read',
    '/auto/file/export-name' => 'route_auto_file_export_name',
    '/api/json/file/export-name' => 'route_api_json_file_export_name',
    '/json/sqli/error' => 'route_json_sqli_error',
    '/api/json/sqli/error' => 'route_api_json_sqli_error',
    '/auto/sqli/error' => 'route_auto_sqli_error',
    '/auto/sqli/search-filter' => 'route_auto_sqli_search_filter',
    '/api/json/sqli/search-filter' => 'route_api_json_sqli_search_filter',
    '/auto/sqli/sort-clause' => 'route_auto_sqli_sort_clause',
    '/api/json/sqli/sort-clause' => 'route_api_json_sqli_sort_clause',
    '/auto/sqli/batch-lookup' => 'route_auto_sqli_batch_lookup',
    '/api/json/sqli/batch-lookup' => 'route_api_json_sqli_batch_lookup',
    '/auto/sqli/graphql-user' => 'route_auto_sqli_graphql_user',
    '/api/json/sqli/graphql-user' => 'route_api_json_sqli_graphql_user',
    '/auto/sqli/report-range' => 'route_auto_sqli_report_range',
    '/api/json/sqli/report-range' => 'route_api_json_sqli_report_range',
    '/auto/sqli/ids-array' => 'route_auto_sqli_ids_array',
    '/api/json/sqli/ids-array' => 'route_api_json_sqli_ids_array',
    '/auto/sqli/json-operator' => 'route_auto_sqli_json_operator',
    '/api/json/sqli/json-operator' => 'route_api_json_sqli_json_operator',
    '/auto/sqli/join-fragment' => 'route_auto_sqli_join_fragment',
    '/api/json/sqli/join-fragment' => 'route_api_json_sqli_join_fragment',
    '/auto/sqli/having-metric' => 'route_auto_sqli_having_metric',
    '/api/json/sqli/having-metric' => 'route_api_json_sqli_having_metric',
    '/auto/sqli/limit-offset' => 'route_auto_sqli_limit_offset',
    '/api/json/sqli/limit-offset' => 'route_api_json_sqli_limit_offset',
    '/auto/sqli/json-search-doc' => 'route_auto_sqli_json_search_doc',
    '/api/json/sqli/json-search-doc' => 'route_api_json_sqli_json_search_doc',
    '/idor/order' => 'route_idor_order',
    '/auto/xss/stored-comment' => 'route_auto_xss_stored_comment',
    '/api/json/xss/stored-comment' => 'route_api_json_xss_stored_comment',
    '/auto/xss/profile-card' => 'route_auto_xss_profile_card',
    '/api/json/xss/profile-card' => 'route_api_json_xss_profile_card',
    '/auto/xss/dom-fragment' => 'route_auto_xss_dom_fragment',
    '/api/json/xss/dom-fragment' => 'route_api_json_xss_dom_fragment',
    '/auto/xss/markdown-preview' => 'route_auto_xss_markdown_preview',
    '/api/json/xss/markdown-preview' => 'route_api_json_xss_markdown_preview',
    '/auto/xss/svg-avatar' => 'route_auto_xss_svg_avatar',
    '/api/json/xss/svg-avatar' => 'route_api_json_xss_svg_avatar',
    '/auto/xss/json-error-message' => 'route_auto_xss_json_error_message',
    '/api/json/xss/json-error-message' => 'route_api_json_xss_json_error_message',
    '/auto/xss/notification-template' => 'route_auto_xss_notification_template',
    '/api/json/xss/notification-template' => 'route_api_json_xss_notification_template',
    '/auto/xss/table-cell' => 'route_auto_xss_table_cell',
    '/api/json/xss/table-cell' => 'route_api_json_xss_table_cell',
    '/auto/xss/email-preview' => 'route_auto_xss_email_preview',
    '/api/json/xss/email-preview' => 'route_api_json_xss_email_preview',
    '/auto/idor/order' => 'route_auto_idor_order',
    '/api/json/idor/order' => 'route_api_json_idor_order',
    '/auto/idor/account-balance' => 'route_auto_idor_account_balance',
    '/api/json/idor/account-balance' => 'route_api_json_idor_account_balance',
    '/auto/idor/invoice-export' => 'route_auto_idor_invoice_export',
    '/api/json/idor/invoice-export' => 'route_api_json_idor_invoice_export',
    '/auto/idor/team-settings' => 'route_auto_idor_team_settings',
    '/api/json/idor/team-settings' => 'route_api_json_idor_team_settings',
    '/auto/idor/project-role' => 'route_auto_idor_project_role',
    '/api/json/idor/project-role' => 'route_api_json_idor_project_role',
    '/auto/idor/api-key-read' => 'route_auto_idor_api_key_read',
    '/api/json/idor/api-key-read' => 'route_api_json_idor_api_key_read',
    '/auto/auth/mass-assignment-role' => 'route_auto_auth_mass_assignment_role',
    '/api/json/auth/mass-assignment-role' => 'route_api_json_auth_mass_assignment_role',
    '/auto/auth/debug-impersonate' => 'route_auto_auth_debug_impersonate',
    '/api/json/auth/debug-impersonate' => 'route_api_json_auth_debug_impersonate',
    '/auto/auth/password-reset-token' => 'route_auto_auth_password_reset_token',
    '/api/json/auth/password-reset-token' => 'route_api_json_auth_password_reset_token',
    '/auto/auth/oauth-callback' => 'route_auto_auth_oauth_callback',
    '/api/json/auth/oauth-callback' => 'route_api_json_auth_oauth_callback',
    '/auto/auth/jwt-none' => 'route_auto_auth_jwt_none',
    '/api/json/auth/jwt-none' => 'route_api_json_auth_jwt_none',
    '/auto/state/change-email' => 'route_auto_state_change_email',
    '/api/json/state/change-email' => 'route_api_json_state_change_email',
    '/auto/state/transfer-log' => 'route_auto_state_transfer_log',
    '/api/json/state/transfer-log' => 'route_api_json_state_transfer_log',
    '/auto/state/feature-flag' => 'route_auto_state_feature_flag',
    '/api/json/state/feature-flag' => 'route_api_json_state_feature_flag',
    '/auto/state/cart-price' => 'route_auto_state_cart_price',
    '/api/json/state/cart-price' => 'route_api_json_state_cart_price',
    '/auto/state/preferences-merge' => 'route_auto_state_preferences_merge',
    '/api/json/state/preferences-merge' => 'route_api_json_state_preferences_merge',
    '/auto/state/inventory-adjust' => 'route_auto_state_inventory_adjust',
    '/api/json/state/inventory-adjust' => 'route_api_json_state_inventory_adjust',
    '/upload/shell' => 'route_upload_shell',
    '/redirect' => 'route_open_redirect',
    '/session/debug' => 'route_session_debug',
    '/auto/session/set-cookie' => 'route_auto_session_set_cookie',
    '/api/json/session/set-cookie' => 'route_api_json_session_set_cookie',
    '/auto/deserialization/php-object' => 'route_auto_deserialization_php_object',
    '/api/json/deserialization/php-object' => 'route_api_json_deserialization_php_object',
    '/auto/deserialization/base64-object' => 'route_auto_deserialization_base64_object',
    '/api/json/deserialization/base64-object' => 'route_api_json_deserialization_base64_object',
    '/auto/deserialization/signed-envelope' => 'route_auto_deserialization_signed_envelope',
    '/api/json/deserialization/signed-envelope' => 'route_api_json_deserialization_signed_envelope',
    '/auto/cors/reflect-origin-json' => 'route_auto_cors_reflect_origin_json',
    '/api/json/cors/reflect-origin-json' => 'route_api_json_cors_reflect_origin_json',
    '/auto/cors/preflight-cache' => 'route_auto_cors_preflight_cache',
    '/api/json/cors/preflight-cache' => 'route_api_json_cors_preflight_cache',
    '/auto/redirect/json-next' => 'route_auto_redirect_json_next',
    '/api/json/redirect/json-next' => 'route_api_json_redirect_json_next',
    '/auto/redirect/deep-link' => 'route_auto_redirect_deep_link',
    '/api/json/redirect/deep-link' => 'route_api_json_redirect_deep_link',
    '/auto/cors/tenant-origin-list' => 'route_auto_cors_tenant_origin_list',
    '/api/json/cors/tenant-origin-list' => 'route_api_json_cors_tenant_origin_list',
);

if (!isset($handlers[$path])) {
    http_response_code(404);
    page_start('Not Found');
    echo '<div class="panel"><p>No route for <code>' . esc($path) . '</code>.</p></div>';
    page_end();
    exit;
}

$handler = $handlers[$path];
$handler($method);

function route_home(string $method): void
{
    page_start('Custom Vulnerable Fuzzer Lab');
    echo '<div class="panel"><p>Use this intentionally vulnerable app to benchmark fuzzer capability across categories and difficulty levels.</p>';
    echo '<p><strong>Difficulty:</strong> <span class="pill">basic</span> <span class="pill">intermediate</span> <span class="pill">constrained</span></p></div>';

    $byCategory = array();
    foreach (catalog_entries() as $entry) {
        $cat = (string) $entry['category'];
        if (!isset($byCategory[$cat])) {
            $byCategory[$cat] = array();
        }
        $byCategory[$cat][] = $entry;
    }

    ksort($byCategory);
    foreach ($byCategory as $cat => $entries) {
        echo '<div class="panel"><h2>' . esc(strtoupper($cat)) . '</h2><ul>';
        foreach ($entries as $entry) {
            $path = (string) $entry['path'];
            $interactivePath = is_scalar($entry['interactive_path'] ?? null) ? (string) $entry['interactive_path'] : null;
            if ($interactivePath !== null && $interactivePath !== '') {
                echo '<li><a href="' . esc($interactivePath) . '">' . esc($interactivePath) . '</a> - ' . esc((string) $entry['description']) . ' (' . esc((string) $entry['difficulty']) . ')';
                echo ' <span class="pill">' . esc((string) $entry['method']) . '</span> API: <code>' . esc($path) . '</code></li>';
                continue;
            }
            $href = explode('?', $path, 2)[0];
            echo '<li><a href="' . esc($path) . '">' . esc($path) . '</a> - ' . esc((string) $entry['description']) . ' (' . esc((string) $entry['difficulty']) . ')</li>';
            if ($href !== $path) {
                echo '<li><a href="' . esc($href) . '">Base route</a></li>';
            }
        }
        echo '</ul></div>';
    }

    page_end();
}

function route_catalog(string $method): void
{
    page_start('Vulnerability Catalog');
    echo '<div class="panel"><p>All vulnerable routes are listed below. Use <code>/catalog.json</code> for machine-readable ingestion.</p></div>';
    echo '<div class="panel"><table><thead><tr><th>Path</th><th>Method</th><th>Category</th><th>Difficulty</th><th>Auth Required</th><th>Description</th><th>Expected Signal</th></tr></thead><tbody>';
    foreach (catalog_entries() as $entry) {
        $path = (string) $entry['path'];
        $interactivePath = is_scalar($entry['interactive_path'] ?? null) ? (string) $entry['interactive_path'] : null;
        $linkPath = ($interactivePath !== null && $interactivePath !== '') ? $interactivePath : $path;
        echo '<tr>';
        echo '<td><a href="' . esc($linkPath) . '">' . esc($linkPath) . '</a>';
        if ($linkPath !== $path) {
            echo '<br><small>API: <code>' . esc($path) . '</code></small>';
        }
        echo '</td>';
        echo '<td>' . esc((string) $entry['method']) . '</td>';
        echo '<td>' . esc((string) $entry['category']) . '</td>';
        echo '<td>' . esc((string) $entry['difficulty']) . '</td>';
        echo '<td>' . (((bool) $entry['auth_required']) ? 'yes' : 'no') . '</td>';
        echo '<td>' . esc((string) $entry['description']) . '</td>';
        echo '<td>' . esc((string) $entry['expected_signal']) . '</td>';
        echo '</tr>';
    }
    echo '</tbody></table></div>';
    page_end();
}

function route_xss_reflected(string $method): void
{
    $input = (string) ($_REQUEST['input'] ?? '<script>alert("xss")</script>');
    page_start('XSS - Reflected');
    render_exploit_guide('/xss/reflected');
    echo '<div class="panel"><p>Input reflected directly:</p>';
    echo '<div>' . $input . '</div>';
    echo '</div>';
    page_end();
}

function route_xss_attr(string $method): void
{
    $input = (string) ($_REQUEST['input'] ?? 'example');
    page_start('XSS - Attribute Context');
    render_exploit_guide('/xss/attr');
    echo '<div class="panel"><p>Attribute injection point:</p>';
    echo '<input value="' . $input . '">';
    echo '</div>';
    page_end();
}

function route_xss_js(string $method): void
{
    $input = (string) ($_REQUEST['input'] ?? "';alert('xss');//");
    page_start('XSS - JavaScript Context');
    render_exploit_guide('/xss/js');
    echo '<div class="panel"><p>JavaScript string context injection point.</p></div>';
    echo '<script>const note = \'" . $input . "\'; console.log(note);</script>';
    page_end();
}

function route_xss_stored(string $method): void
{
    $db = db_connect();
    page_start('XSS - Stored Comments');
    render_exploit_guide('/xss/stored');

    if ($db === null) {
        echo '<div class="panel"><p>Database unavailable.</p></div>';
        page_end();
        return;
    }

    seed_database($db);

    if ($method === 'POST') {
        $body = (string) ($_POST['body'] ?? '');
        $userId = (int) (current_user()['id'] ?? 0);
        $sql = "INSERT INTO comments(user_id, body, created_at) VALUES ($userId, '" . $db->real_escape_string($body) . "', NOW())";
        $db->query($sql);
        header('Location: /xss/stored');
        exit;
    }

    echo '<div class="panel"><form method="post"><label>Comment</label><br><textarea name="body" rows="3" cols="80"></textarea><br><button type="submit">Post</button></form></div>';
    echo '<div class="panel"><h2>Comments</h2>';
    $res = $db->query('SELECT id, user_id, body, created_at FROM comments ORDER BY id DESC LIMIT 30');
    if ($res instanceof mysqli_result) {
        while ($row = $res->fetch_assoc()) {
            echo '<div><strong>#' . (int) $row['id'] . '</strong> user=' . (int) $row['user_id'] . ' at ' . esc((string) $row['created_at']) . '<br>' . (string) $row['body'] . '</div><hr>';
        }
    }
    echo '</div>';

    page_end();
}

function route_xss_filtered(string $method): void
{
    $input = (string) ($_REQUEST['input'] ?? '<svg onload=alert(1)>');
    $filtered = preg_replace('/script|["\']/i', '', $input);
    $filtered = (string) $filtered;

    page_start('XSS - Filtered');
    render_exploit_guide('/xss/filtered');
    echo '<div class="panel"><p>Naive filter removes <code>script</code> and quotes only.</p>';
    echo '<p>Filtered output:</p>';
    echo '<div ' . $filtered . '>hover me</div>';
    echo '</div>';
    page_end();
}

function route_sqli_error(string $method): void
{
    $id = (string) ($_GET['id'] ?? '1');
    $db = db_connect();
    page_start('SQLi - Error Based');
    render_exploit_guide('/sqli/error');

    if ($db === null) {
        echo '<div class="panel"><p>Database unavailable.</p></div>';
        page_end();
        return;
    }

    seed_database($db);
    $sql = "SELECT id, username, email FROM users WHERE id = $id";
    $res = $db->query($sql);

    echo '<div class="panel"><p><strong>SQL:</strong> ' . esc($sql) . '</p>';
    if ($res === false) {
        echo '<pre>SQL ERROR: ' . esc($db->error) . '</pre>';
    } else {
        echo '<pre>';
        while ($row = $res->fetch_assoc()) {
            echo esc(json_encode($row, JSON_UNESCAPED_SLASHES)) . "\n";
        }
        echo '</pre>';
    }
    echo '</div>';
    page_end();
}

function route_sqli_union(string $method): void
{
    $id = (string) ($_GET['id'] ?? '1');
    $db = db_connect();
    page_start('SQLi - Union Based');
    render_exploit_guide('/sqli/union');

    if ($db === null) {
        echo '<div class="panel"><p>Database unavailable.</p></div>';
        page_end();
        return;
    }

    seed_database($db);
    $sql = "SELECT id, username, email FROM users WHERE id = $id";
    $res = $db->query($sql);

    echo '<div class="panel"><p><strong>SQL:</strong> ' . esc($sql) . '</p>';
    if ($res === false) {
        echo '<pre>SQL ERROR: ' . esc($db->error) . '</pre>';
    } else {
        echo '<table><thead><tr><th>ID</th><th>User</th><th>Email</th></tr></thead><tbody>';
        while ($row = $res->fetch_assoc()) {
            echo '<tr><td>' . esc((string) $row['id']) . '</td><td>' . esc((string) $row['username']) . '</td><td>' . esc((string) $row['email']) . '</td></tr>';
        }
        echo '</tbody></table>';
    }
    echo '</div>';
    page_end();
}

function route_sqli_blind_bool(string $method): void
{
    $id = (string) ($_GET['id'] ?? '1');
    $db = db_connect();
    page_start('SQLi - Boolean Blind');
    render_exploit_guide('/sqli/blind-bool');

    if ($db === null) {
        echo '<div class="panel"><p>Database unavailable.</p></div>';
        page_end();
        return;
    }

    seed_database($db);
    $sql = "SELECT COUNT(*) AS c FROM users WHERE id = $id";
    $res = $db->query($sql);
    $count = 0;
    if ($res instanceof mysqli_result) {
        $row = $res->fetch_assoc();
        $count = (int) ($row['c'] ?? 0);
    }

    echo '<div class="panel"><p><strong>SQL:</strong> ' . esc($sql) . '</p>';
    echo '<p>' . ($count > 0 ? 'Welcome back.' : 'No matching user.') . '</p>';
    echo '</div>';
    page_end();
}

function route_sqli_blind_time(string $method): void
{
    $id = (string) ($_GET['id'] ?? '1');
    $db = db_connect();
    page_start('SQLi - Time Blind');
    render_exploit_guide('/sqli/blind-time');

    if ($db === null) {
        echo '<div class="panel"><p>Database unavailable.</p></div>';
        page_end();
        return;
    }

    seed_database($db);
    $sql = "SELECT id FROM users WHERE id = 1 AND ($id)";
    $start = microtime(true);
    $res = $db->query($sql);
    $elapsed = microtime(true) - $start;

    echo '<div class="panel"><p><strong>SQL:</strong> ' . esc($sql) . '</p>';
    if ($res === false) {
        echo '<pre>SQL ERROR: ' . esc($db->error) . '</pre>';
    }
    echo '<p>Elapsed seconds: ' . esc(number_format($elapsed, 3)) . '</p>';
    echo '<p>Try payload style: <code>1 OR IF(1=1,SLEEP(3),0)</code></p></div>';
    page_end();
}

function route_sqli_constrained(string $method): void
{
    $id = (string) ($_GET['id'] ?? 'alice');
    $db = db_connect();
    page_start('SQLi - Constrained/Filtered');
    render_exploit_guide('/sqli/constrained');

    if ($db === null) {
        echo '<div class="panel"><p>Database unavailable.</p></div>';
        page_end();
        return;
    }

    seed_database($db);
    $filtered = preg_replace('/union|sleep|select|--|;|\\s+/i', '', $id);
    $filtered = (string) $filtered;
    $sql = "SELECT id, username FROM users WHERE username = '$filtered'";
    $res = $db->query($sql);

    echo '<div class="panel"><p>Naive blacklist removed selected keywords and whitespace.</p>';
    echo '<p><strong>Original:</strong> ' . esc($id) . '</p>';
    echo '<p><strong>Filtered:</strong> ' . esc($filtered) . '</p>';
    echo '<p><strong>SQL:</strong> ' . esc($sql) . '</p>';

    if ($res === false) {
        echo '<pre>SQL ERROR: ' . esc($db->error) . '</pre>';
    } else {
        while ($row = $res->fetch_assoc()) {
            echo '<div>User: ' . esc((string) $row['username']) . ' (#' . esc((string) $row['id']) . ')</div>';
        }
    }
    echo '</div>';
    page_end();
}

function route_sqli_login(string $method): void
{
    $db = db_connect();
    page_start('SQLi - Login Bypass');
    render_exploit_guide('/sqli/login');

    if ($db === null) {
        echo '<div class="panel"><p>Database unavailable.</p></div>';
        page_end();
        return;
    }

    seed_database($db);

    $message = 'Submit credentials.';
    if ($method === 'POST') {
        $username = (string) ($_POST['username'] ?? '');
        $password = (string) ($_POST['password'] ?? '');
        $sql = "SELECT id, username, role FROM users WHERE username = '$username' AND password = '$password' LIMIT 1";
        $res = $db->query($sql);
        if ($res instanceof mysqli_result && ($row = $res->fetch_assoc())) {
            $message = 'Authenticated as ' . (string) $row['username'];
        } else {
            $message = 'Login failed.';
        }
        echo '<div class="panel"><p><strong>Executed SQL:</strong> ' . esc($sql) . '</p></div>';
    }

    echo '<div class="panel"><p>' . esc($message) . '</p>';
    echo '<form method="post"><label>User</label><br><input type="text" name="username"><br><label>Password</label><br><input type="text" name="password"><br><button type="submit">Login</button></form>';
    echo '</div>';
    page_end();
}

function route_auth_login(string $method): void
{
    $db = db_connect();
    page_start('Auth Login');

    if ($db === null) {
        echo '<div class="panel"><p>Database unavailable.</p></div>';
        page_end();
        return;
    }

    seed_database($db);

    $message = 'Use seeded credentials: alice/synthetic-lab-alice-only, bob/synthetic-lab-bob-only, admin/synthetic-lab-admin-only.';
    if ($method === 'POST') {
        $username = (string) ($_POST['username'] ?? '');
        $password = (string) ($_POST['password'] ?? '');
        $sql = "SELECT id, username, role, email FROM users WHERE username='" . $db->real_escape_string($username) . "' AND password='" . $db->real_escape_string($password) . "' LIMIT 1";
        $res = $db->query($sql);
        if ($res instanceof mysqli_result && ($row = $res->fetch_assoc())) {
            $_SESSION['user'] = array(
                'id' => (int) $row['id'],
                'username' => (string) $row['username'],
                'role' => (string) $row['role'],
                'email' => (string) $row['email'],
            );
            header('Location: /');
            exit;
        }
        $message = 'Invalid credentials.';
    }

    echo '<div class="panel"><p>' . esc($message) . '</p><form method="post"><label>User</label><br><input type="text" name="username"><br><label>Password</label><br><input type="password" name="password"><br><button type="submit">Sign in</button></form></div>';
    page_end();
}

function route_auth_logout(string $method): void
{
    $_SESSION = array();
    session_destroy();
    header('Location: /');
    exit;
}

function route_csrf_change_email(string $method): void
{
    require_login();
    $db = db_connect();
    page_start('CSRF - Change Email (No Token)');
    render_exploit_guide('/csrf/change-email');

    if ($db === null) {
        echo '<div class="panel"><p>Database unavailable.</p></div>';
        page_end();
        return;
    }

    $user = current_user();
    $msg = 'No CSRF protection on this endpoint.';
    if ($method === 'POST') {
        $email = (string) ($_POST['email'] ?? '');
        $uid = (int) $user['id'];
        $sql = "UPDATE users SET email='" . $db->real_escape_string($email) . "' WHERE id=$uid";
        $db->query($sql);
        $_SESSION['user']['email'] = $email;
        $msg = 'Email updated to ' . $email;
    }

    echo '<div class="panel"><p>' . esc($msg) . '</p><form method="post"><label>New Email</label><br><input type="text" name="email" value="' . esc((string) $user['email']) . '"><br><button type="submit">Update</button></form></div>';
    page_end();
}

function route_csrf_transfer(string $method): void
{
    require_login();
    $db = db_connect();
    page_start('CSRF - Transfer (No Token)');
    render_exploit_guide('/csrf/transfer');

    if ($db === null) {
        echo '<div class="panel"><p>Database unavailable.</p></div>';
        page_end();
        return;
    }

    seed_database($db);
    $user = current_user();
    $msg = 'No CSRF token required.';

    if ($method === 'POST') {
        $to = (int) ($_POST['to_user_id'] ?? 0);
        $amount = (float) ($_POST['amount'] ?? 0);
        $from = (int) $user['id'];

        $db->query("UPDATE accounts SET balance = balance - $amount WHERE user_id = $from");
        $db->query("UPDATE accounts SET balance = balance + $amount WHERE user_id = $to");
        $db->query("INSERT INTO transfer_log(from_user_id,to_user_id,amount,created_at) VALUES($from,$to,$amount,NOW())");
        $msg = 'Transfer submitted from user #' . $from . ' to #' . $to . ' amount=' . $amount;
    }

    echo '<div class="panel"><p>' . esc($msg) . '</p><form method="post"><label>To User ID</label><br><input type="text" name="to_user_id" value="2"><br><label>Amount</label><br><input type="text" name="amount" value="10"><br><button type="submit">Transfer</button></form></div>';

    $res = $db->query('SELECT user_id, balance FROM accounts ORDER BY user_id');
    echo '<div class="panel"><h2>Balances</h2><pre>';
    if ($res instanceof mysqli_result) {
        while ($row = $res->fetch_assoc()) {
            echo 'user ' . (int) $row['user_id'] . ' => ' . (string) $row['balance'] . "\n";
        }
    }
    echo '</pre></div>';
    page_end();
}

function route_csrf_weak_token(string $method): void
{
    require_login();
    $db = db_connect();
    page_start('CSRF - Weak Token');
    render_exploit_guide('/csrf/weak-token');

    if ($db === null) {
        echo '<div class="panel"><p>Database unavailable.</p></div>';
        page_end();
        return;
    }

    $user = current_user();
    $weakToken = md5((string) $user['id']);
    $msg = 'Token is weak/predictable.';

    if ($method === 'POST') {
        $email = (string) ($_POST['email'] ?? '');
        $token = (string) ($_POST['csrf_token'] ?? '');
        if ($token === $weakToken) {
            $uid = (int) $user['id'];
            $db->query("UPDATE users SET email='" . $db->real_escape_string($email) . "' WHERE id=$uid");
            $_SESSION['user']['email'] = $email;
            $msg = 'Weak token accepted. Email updated.';
        } else {
            $msg = 'Token rejected.';
        }
    }

    echo '<div class="panel"><p>' . esc($msg) . '</p>';
    echo '<p>Displayed token (predictable): <code>' . esc($weakToken) . '</code></p>';
    echo '<form method="post"><label>Email</label><br><input type="text" name="email" value="' . esc((string) $user['email']) . '"><br><label>csrf_token</label><br><input type="text" name="csrf_token" value="' . esc($weakToken) . '"><br><button type="submit">Submit</button></form></div>';
    page_end();
}

function route_rce_system(string $method): void
{
    $cmd = (string) ($_GET['cmd'] ?? 'id');
    page_start('RCE - system()');
    render_exploit_guide('/rce/system');
    echo '<div class="panel"><p>Command: <code>' . esc($cmd) . '</code></p><pre>';
    @system($cmd);
    echo '</pre></div>';
    page_end();
}

function route_rce_filtered(string $method): void
{
    $cmd = (string) ($_GET['cmd'] ?? 'whoami');
    $filtered = str_ireplace(array(';', '&', '|', '$(', '`'), '', $cmd);
    page_start('RCE - Weak Filter');
    render_exploit_guide('/rce/filtered');
    echo '<div class="panel"><p>Original: <code>' . esc($cmd) . '</code></p><p>Filtered: <code>' . esc($filtered) . '</code></p><pre>';
    $output = @shell_exec($filtered);
    echo esc((string) $output);
    echo '</pre></div>';
    page_end();
}

function route_rce_eval(string $method): void
{
    $code = (string) ($_GET['code'] ?? 'echo "eval path\n";');
    page_start('RCE - eval()');
    render_exploit_guide('/rce/eval');
    echo '<div class="panel"><p>Executing untrusted PHP:</p><pre>' . esc($code) . '</pre><pre>';
    @eval($code);
    echo '</pre></div>';
    page_end();
}

function route_json_rce_system(string $method): void
{
    render_json_playground(
        'JSON RCE - system()',
        '/api/json/rce/system',
        'task.command',
        'system($command)',
        array(
            'task' => array('command' => 'id'),
            'metadata' => array('source' => 'json-lab'),
        )
    );
}

function route_api_json_rce_system(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }

    $task = is_array($payload['task'] ?? null) ? $payload['task'] : array();
    $cmd = (string) ($task['command'] ?? 'id');
    $exitCode = 0;

    ob_start();
    @system($cmd, $exitCode);
    $output = (string) ob_get_clean();

    json_response(array(
        'ok' => true,
        'category' => 'rce',
        'sink' => 'system',
        'command' => $cmd,
        'exit_code' => $exitCode,
        'output_preview' => substr($output, 0, 4000),
    ));
}

function route_ssrf_fetch(string $method): void
{
    $url = (string) ($_GET['url'] ?? 'http://127.0.0.1:9/');
    page_start('SSRF - Raw Fetch');
    render_exploit_guide('/ssrf/fetch');
    $body = @file_get_contents($url);
    echo '<div class="panel"><p>Target URL: <code>' . esc($url) . '</code></p>';
    if ($body === false) {
        echo '<pre>fetch failed</pre>';
    } else {
        echo '<pre>' . esc(substr($body, 0, 2000)) . '</pre>';
    }
    echo '</div>';
    page_end();
}

function route_ssrf_weak_filter(string $method): void
{
    $url = (string) ($_GET['url'] ?? 'http://127.1:9/');
    page_start('SSRF - Weak Host Filter');
    render_exploit_guide('/ssrf/weak-filter');
    if (stripos($url, '127.0.0.1') !== false || stripos($url, 'localhost') !== false) {
        echo '<div class="panel"><p>Blocked by naive filter.</p></div>';
        page_end();
        return;
    }

    $body = @file_get_contents($url);
    echo '<div class="panel"><p>Filter accepted URL: <code>' . esc($url) . '</code></p>';
    echo '<pre>' . esc(substr((string) $body, 0, 2000)) . '</pre></div>';
    page_end();
}

function route_ssrf_redirect(string $method): void
{
    $url = (string) ($_GET['url'] ?? 'http://127.0.0.1:9/redirect?next=http://127.0.0.1:9/session/debug');
    page_start('SSRF - Redirect Follow');
    render_exploit_guide('/ssrf/redirect');

    $body = false;
    if (function_exists('curl_init')) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_MAXREDIRS, 5);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        $body = curl_exec($ch);
        curl_close($ch);
    } else {
        $ctx = stream_context_create(array('http' => array('follow_location' => 1, 'max_redirects' => 5, 'timeout' => 5)));
        $body = @file_get_contents($url, false, $ctx);
    }

    echo '<div class="panel"><p>Target URL: <code>' . esc($url) . '</code></p><pre>' . esc(substr((string) $body, 0, 2000)) . '</pre></div>';
    page_end();
}

function route_file_lfi(string $method): void
{
    $page = (string) ($_GET['page'] ?? 'home');
    $cfg = app_config();
    $target = $cfg['lfi_pages_dir'] . '/' . $page . '.php';

    page_start('LFI - include()');
    render_exploit_guide('/file/lfi');
    echo '<div class="panel"><p>Including: <code>' . esc($target) . '</code></p></div>';
    echo '<div class="panel">';
    @include $target;
    echo '</div>';
    page_end();
}

function route_file_lfi_constrained(string $method): void
{
    $page = (string) ($_GET['page'] ?? 'home');
    $cfg = app_config();
    $sanitized = str_replace(array('../', '..\\', '%00', "\0"), '', $page);
    $target = $cfg['lfi_pages_dir'] . '/' . $sanitized . '.php';

    page_start('LFI - Constrained');
    render_exploit_guide('/file/lfi-constrained');
    echo '<div class="panel"><p>Original: <code>' . esc($page) . '</code></p><p>Sanitized: <code>' . esc($sanitized) . '</code></p><p>Including: <code>' . esc($target) . '</code></p></div>';
    echo '<div class="panel">';
    @include $target;
    echo '</div>';
    page_end();
}

function route_file_rfi(string $method): void
{
    ini_set('allow_url_include', '1');
    $url = (string) ($_GET['url'] ?? 'php://filter/resource=/etc/hosts');

    page_start('RFI - include remote');
    render_exploit_guide('/file/rfi');
    echo '<div class="panel"><p>Including URL: <code>' . esc($url) . '</code></p><pre>';
    @include $url;
    echo '</pre></div>';
    page_end();
}

function route_json_file_lfi(string $method): void
{
    render_json_playground(
        'JSON LFI - include/read',
        '/api/json/file/lfi',
        'file.page + options.suffix',
        'include + file_get_contents',
        array(
            'file' => array('page' => 'home'),
            'options' => array('suffix' => '.php'),
        )
    );
}

function route_api_json_file_lfi(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }

    $file = is_array($payload['file'] ?? null) ? $payload['file'] : array();
    $options = is_array($payload['options'] ?? null) ? $payload['options'] : array();
    $page = (string) ($file['page'] ?? 'home');
    $suffix = (string) ($options['suffix'] ?? '.php');
    $cfg = app_config();
    $target = $cfg['lfi_pages_dir'] . '/' . $page . $suffix;

    ob_start();
    @include $target;
    $included = (string) ob_get_clean();
    $readBody = @file_get_contents($target);

    json_response(array(
        'ok' => true,
        'category' => 'lfi',
        'sink' => 'include+file_get_contents',
        'page' => $page,
        'suffix' => $suffix,
        'target' => $target,
        'included_output_preview' => substr($included, 0, 4000),
        'read_preview' => is_string($readBody) ? substr($readBody, 0, 4000) : null,
        'read_failed' => !is_string($readBody),
    ));
}

function route_json_sqli_error(string $method): void
{
    render_json_playground(
        'JSON SQLi - Error Based',
        '/api/json/sqli/error',
        'lookup.id',
        'mysqli::query',
        array(
            'lookup' => array('id' => '1'),
            'options' => array('limit' => '10'),
        )
    );
}

function route_api_json_sqli_error(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }

    $db = db_connect();
    if ($db === null) {
        json_response(array(
            'ok' => false,
            'error' => 'database_unavailable',
        ), 503);
        return;
    }

    seed_database($db);
    $lookup = is_array($payload['lookup'] ?? null) ? $payload['lookup'] : array();
    $options = is_array($payload['options'] ?? null) ? $payload['options'] : array();
    $id = (string) ($lookup['id'] ?? '1');
    $limit = (string) ($options['limit'] ?? '10');
    $sql = "SELECT id, username, email FROM users WHERE id = $id LIMIT $limit";
    $res = $db->query($sql);

    if ($res === false) {
        json_response(array(
            'ok' => false,
            'category' => 'sqli',
            'sink' => 'mysqli::query',
            'sql' => $sql,
            'db_error' => $db->error,
        ));
        return;
    }

    $rows = array();
    if ($res instanceof mysqli_result) {
        while ($row = $res->fetch_assoc()) {
            $rows[] = $row;
        }
    }

    json_response(array(
        'ok' => true,
        'category' => 'sqli',
        'sink' => 'mysqli::query',
        'sql' => $sql,
        'rows' => $rows,
    ));
}

function route_idor_order(string $method): void
{
    require_login();
    $db = db_connect();
    page_start('IDOR - Order Access');
    render_exploit_guide('/idor/order');

    if ($db === null) {
        echo '<div class="panel"><p>Database unavailable.</p></div>';
        page_end();
        return;
    }

    seed_database($db);
    $id = (string) ($_GET['id'] ?? '1');
    $mode = (string) ($_GET['mode'] ?? 'vuln');
    $user = current_user();

    if ($mode === 'safe') {
        $uid = (int) $user['id'];
        $sql = "SELECT id, owner_user_id, item_name, total_amount, status FROM orders WHERE id = $id AND owner_user_id = $uid";
    } else {
        $sql = "SELECT id, owner_user_id, item_name, total_amount, status FROM orders WHERE id = $id";
    }

    $res = $db->query($sql);
    echo '<div class="panel"><p>Mode: <code>' . esc($mode) . '</code></p><p>SQL: <code>' . esc($sql) . '</code></p><pre>';
    if ($res instanceof mysqli_result) {
        while ($row = $res->fetch_assoc()) {
            echo esc(json_encode($row, JSON_UNESCAPED_SLASHES)) . "\n";
        }
    } else {
        echo 'query failed: ' . esc((string) $db->error);
    }
    echo '</pre></div>';
    page_end();
}

function route_upload_shell(string $method): void
{
    $cfg = app_config();
    $uploadDir = $cfg['upload_dir'];
    if (!is_dir($uploadDir)) {
        @mkdir($uploadDir, 0777, true);
    }

    page_start('Upload - Weak Validation');
    render_exploit_guide('/upload/shell');

    $msg = 'Upload allows executable extensions (.php, .phtml, .php5).';
    if ($method === 'POST' && isset($_FILES['payload'])) {
        $name = (string) ($_FILES['payload']['name'] ?? '');
        $tmp = (string) ($_FILES['payload']['tmp_name'] ?? '');
        $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
        $allowed = array('php', 'phtml', 'php5', 'txt', 'jpg');
        if (in_array($ext, $allowed, true) && $tmp !== '') {
            $destName = date('Ymd_His') . '_' . preg_replace('/[^a-zA-Z0-9._-]/', '_', $name);
            $dest = $uploadDir . '/' . $destName;
            if (@move_uploaded_file($tmp, $dest)) {
                $msg = 'Uploaded: /uploads/' . $destName;
            } else {
                $msg = 'Upload failed.';
            }
        } else {
            $msg = 'Extension blocked.';
        }
    }

    echo '<div class="panel"><p>' . esc($msg) . '</p>';
    echo '<form method="post" enctype="multipart/form-data"><input type="file" name="payload"><button type="submit">Upload</button></form>';
    echo '</div>';

    echo '<div class="panel"><h2>Uploaded Files</h2><ul>';
    $files = glob($uploadDir . '/*');
    if (is_array($files)) {
        foreach ($files as $file) {
            $base = basename($file);
            echo '<li><a href="/uploads/' . esc($base) . '">' . esc($base) . '</a></li>';
        }
    }
    echo '</ul></div>';

    page_end();
}

function route_open_redirect(string $method): void
{
    $next = (string) ($_GET['next'] ?? 'https://example.org');
    $go = (string) ($_GET['go'] ?? '');
    if ($go === '1') {
        header('Location: ' . $next, true, 302);
        exit;
    }

    page_start('Open Redirect');
    render_exploit_guide('/redirect');
    echo '<div class="panel"><p>Current target: <code>' . esc($next) . '</code></p>';
    echo '<p>Use <code>?go=1&amp;next=...</code> to execute the redirect response.</p>';
    echo '<p><a href="/redirect?go=1&amp;next=' . rawurlencode($next) . '">Execute redirect now</a></p></div>';
    page_end();
}

function route_session_debug(string $method): void
{
    if (isset($_GET['set'])) {
        $name = (string) ($_GET['set'] ?? 'debug');
        $value = (string) ($_GET['value'] ?? '1');
        setcookie($name, $value, array('expires' => time() + 3600, 'path' => '/', 'secure' => false, 'httponly' => false, 'samesite' => 'Lax'));
        $_COOKIE[$name] = $value;
    }

    page_start('Session / Cookie Debug');
    render_exploit_guide('/session/debug');
    echo '<div class="panel"><p>Session and cookie details are intentionally exposed.</p>';
    echo '<pre>' . esc(json_encode(array(
        'session_id' => session_id(),
        'session_name' => session_name(),
        'session' => $_SESSION,
        'cookies' => $_COOKIE,
        'headers' => function_exists('getallheaders') ? getallheaders() : array(),
    ), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)) . '</pre>';
    echo '<p>Set insecure cookie: <a href="/session/debug?set=fuzzer_token&value=demo">/session/debug?set=fuzzer_token&value=demo</a></p></div>';
    page_end();
}

function route_auto_rce_system(string $method): void
{
    render_auto_json_trigger(
        'Auto JSON RCE - system()',
        '/auto/rce/system',
        'rce',
        '/api/json/rce/system',
        'task.command',
        'system($command)',
        array(
            'task' => array('command' => 'printf auto_rce_ok'),
            'metadata' => array('source' => 'auto-json-lab', 'trigger' => 'page_load'),
        )
    );
}

function route_auto_file_lfi(string $method): void
{
    render_auto_json_trigger(
        'Auto JSON LFI - include/read',
        '/auto/file/lfi',
        'lfi',
        '/api/json/file/lfi',
        'file.page + options.suffix',
        'include + file_get_contents',
        array(
            'file' => array('page' => 'home'),
            'options' => array('suffix' => '.php'),
            'metadata' => array('source' => 'auto-json-lab', 'trigger' => 'page_load'),
        )
    );
}

function route_auto_sqli_error(string $method): void
{
    render_auto_json_trigger(
        'Auto JSON SQLi - Error Based',
        '/auto/sqli/error',
        'sqli',
        '/api/json/sqli/error',
        'lookup.id',
        'mysqli::query',
        array(
            'lookup' => array('id' => "1'"),
            'options' => array('limit' => '10'),
            'metadata' => array('source' => 'auto-json-lab', 'trigger' => 'page_load'),
        )
    );
}

function route_auto_ssrf_fetch(string $method): void
{
    render_auto_json_trigger(
        'Auto JSON SSRF - Server Fetch',
        '/auto/ssrf/fetch',
        'ssrf',
        '/api/json/ssrf/fetch',
        'request.url',
        'file_get_contents($url)',
        array(
            'request' => array('url' => 'data://text/plain,auto_ssrf_fetch_ok'),
            'options' => array('timeout_seconds' => 4),
            'metadata' => array('source' => 'auto-json-lab', 'trigger' => 'page_load'),
        )
    );
}

function route_auto_xss_stored_comment(string $method): void
{
    render_auto_json_trigger(
        'Auto JSON XSS - Stored Comment',
        '/auto/xss/stored-comment',
        'xss',
        '/api/json/xss/stored-comment',
        'comment.body',
        'stored comment render without output encoding',
        array(
            'actor' => array('user_id' => '1'),
            'comment' => array('body' => "AUTO_JSON_XSS:<svg/onload=alert('auto-json-xss')>"),
            'metadata' => array('source' => 'auto-json-lab', 'trigger' => 'page_load'),
        )
    );
}

function route_auto_idor_order(string $method): void
{
    render_auto_json_trigger(
        'Auto JSON IDOR - Order Lookup',
        '/auto/idor/order',
        'idor',
        '/api/json/idor/order',
        'lookup.order_id',
        'object lookup without owner enforcement',
        array(
            'actor' => array('user_id' => '1'),
            'lookup' => array('order_id' => '2'),
            'options' => array('mode' => 'vuln'),
            'metadata' => array('source' => 'auto-json-lab', 'trigger' => 'page_load'),
        )
    );
}

function route_auto_state_change_email(string $method): void
{
    render_auto_json_trigger(
        'Auto JSON State Change - Email',
        '/auto/state/change-email',
        'state_change',
        '/api/json/state/change-email',
        'profile.email',
        'UPDATE users without CSRF/auth enforcement',
        array(
            'user' => array('id' => '1'),
            'profile' => array('email' => 'alice+auto-json@example.test'),
            'metadata' => array('source' => 'auto-json-lab', 'trigger' => 'page_load'),
        )
    );
}

function route_auto_session_set_cookie(string $method): void
{
    render_auto_json_trigger(
        'Auto JSON Session - Set Cookie',
        '/auto/session/set-cookie',
        'session',
        '/api/json/session/set-cookie',
        'cookie.name + cookie.value',
        'setcookie() with insecure attributes',
        array(
            'cookie' => array('name' => 'auto_json_token', 'value' => 'demo-auto-json'),
            'options' => array('max_age' => '3600'),
            'metadata' => array('source' => 'auto-json-lab', 'trigger' => 'page_load'),
        )
    );
}

function route_auto_rce_argv_array(string $method): void
{
    render_auto_json_trigger(
        'Auto JSON RCE - Argv Array',
        '/auto/rce/argv-array',
        'rce',
        '/api/json/rce/argv-array',
        'exec.binary + exec.argv[0]',
        'system($binary . " " . implode(" ", $argv))',
        array(
            'exec' => array('binary' => 'printf', 'argv' => array('auto_rce_array_ok')),
            'metadata' => array('source' => 'auto-json-lab', 'shape' => 'array', 'trigger' => 'page_load'),
        )
    );
}

function route_auto_rce_workflow_step(string $method): void
{
    render_auto_json_trigger(
        'Auto JSON RCE - Workflow Step',
        '/auto/rce/workflow-step',
        'rce',
        '/api/json/rce/workflow-step',
        'workflow.steps[1].params.command',
        'system($step["params"]["command"])',
        array(
            'workflow' => array(
                'steps' => array(
                    array('name' => 'prep', 'params' => array('note' => 'ignored')),
                    array('name' => 'run', 'params' => array('command' => 'printf auto_rce_workflow_ok')),
                ),
            ),
            'metadata' => array('source' => 'auto-json-lab', 'shape' => 'workflow', 'trigger' => 'page_load'),
        )
    );
}

function route_auto_sqli_search_filter(string $method): void
{
    render_auto_json_trigger(
        'Auto JSON SQLi - Search Filter',
        '/auto/sqli/search-filter',
        'sqli',
        '/api/json/sqli/search-filter',
        'search.criteria.username',
        'mysqli::query',
        array(
            'search' => array('criteria' => array('username' => "alice' OR '1'='1")),
            'metadata' => array('source' => 'auto-json-lab', 'shape' => 'nested_filter', 'trigger' => 'page_load'),
        )
    );
}

function route_auto_sqli_sort_clause(string $method): void
{
    render_auto_json_trigger(
        'Auto JSON SQLi - Sort Clause',
        '/auto/sqli/sort-clause',
        'sqli',
        '/api/json/sqli/sort-clause',
        'grid.sort.field + grid.sort.direction',
        'mysqli::query ORDER BY concatenation',
        array(
            'grid' => array('sort' => array('field' => 'id', 'direction' => 'DESC')),
            'metadata' => array('source' => 'auto-json-lab', 'shape' => 'sort_clause', 'trigger' => 'page_load'),
        )
    );
}

function route_auto_sqli_batch_lookup(string $method): void
{
    render_auto_json_trigger(
        'Auto JSON SQLi - Batch Lookup',
        '/auto/sqli/batch-lookup',
        'sqli',
        '/api/json/sqli/batch-lookup',
        'requests[options.use_index].id',
        'mysqli::query',
        array(
            'requests' => array(array('id' => '1'), array('id' => '2 OR 1=1')),
            'options' => array('use_index' => 1),
            'metadata' => array('source' => 'auto-json-lab', 'shape' => 'batch_selector', 'trigger' => 'page_load'),
        )
    );
}

function route_auto_file_lang_include(string $method): void
{
    render_auto_json_trigger(
        'Auto JSON File - Language Include',
        '/auto/file/lang-include',
        'lfi',
        '/api/json/file/lang-include',
        'view.locale + view.template',
        'include + file_get_contents',
        array(
            'view' => array('locale' => '..', 'template' => 'pages/home'),
            'metadata' => array('source' => 'auto-json-lab', 'shape' => 'nested_path', 'trigger' => 'page_load'),
        )
    );
}

function route_auto_file_path_parts(string $method): void
{
    render_auto_json_trigger(
        'Auto JSON File - Path Parts',
        '/auto/file/path-parts',
        'lfi',
        '/api/json/file/path-parts',
        'document.path_parts[] + document.extension',
        'file_get_contents',
        array(
            'document' => array('path_parts' => array('home'), 'extension' => 'php'),
            'metadata' => array('source' => 'auto-json-lab', 'shape' => 'path_parts_array', 'trigger' => 'page_load'),
        )
    );
}

function route_auto_file_write_json(string $method): void
{
    render_auto_json_trigger(
        'Auto JSON File - Write JSON',
        '/auto/file/write-json',
        'file_write',
        '/api/json/file/write-json',
        'artifact.content',
        'file_put_contents',
        array(
            'artifact' => array('name' => 'auto_json_write.json', 'content' => '{"auto_file_write":"ok"}'),
            'metadata' => array('source' => 'auto-json-lab', 'shape' => 'write_artifact', 'trigger' => 'page_load'),
        )
    );
}

function route_auto_ssrf_webhook_basic(string $method): void
{
    render_auto_json_trigger(
        'Auto JSON SSRF - Webhook Basic',
        '/auto/ssrf/webhook-basic',
        'ssrf',
        '/api/json/ssrf/webhook-basic',
        'webhook_url',
        'file_get_contents($webhookUrl)',
        array(
            'webhook_url' => 'data://text/plain,auto_ssrf_webhook_ok',
            'metadata' => array('source' => 'auto-json-lab', 'shape' => 'scalar', 'trigger' => 'page_load'),
        )
    );
}

function route_auto_ssrf_events_callback(string $method): void
{
    render_auto_json_trigger(
        'Auto JSON SSRF - Events Callback',
        '/auto/ssrf/events-callback',
        'ssrf',
        '/api/json/ssrf/events-callback',
        'events[1].delivery.callback.href',
        'file_get_contents($callbackHref)',
        array(
            'events' => array(
                array('type' => 'noop'),
                array('type' => 'notify', 'delivery' => array('callback' => array('href' => 'data://text/plain,auto_ssrf_event_ok'))),
            ),
            'metadata' => array('source' => 'auto-json-lab', 'shape' => 'deep_callback', 'trigger' => 'page_load'),
        )
    );
}

function route_auto_xss_profile_card(string $method): void
{
    render_auto_json_trigger(
        'Auto JSON XSS - Profile Card',
        '/auto/xss/profile-card',
        'xss',
        '/api/json/xss/profile-card',
        'profile.display_name',
        'HTML template concatenation',
        array(
            'profile' => array('display_name' => '<img src=x onerror=alert(1)>', 'bio' => 'auto profile card'),
            'metadata' => array('source' => 'auto-json-lab', 'shape' => 'profile_object', 'trigger' => 'page_load'),
        )
    );
}

function route_auto_xss_dom_fragment(string $method): void
{
    render_auto_json_trigger(
        'Auto JSON XSS - DOM Fragment',
        '/auto/xss/dom-fragment',
        'xss',
        '/api/json/xss/dom-fragment',
        'widgets[0].html',
        'client DOM innerHTML contract',
        array(
            'widgets' => array(array('slot' => 'summary', 'html' => '<svg/onload=alert(1)>')),
            'metadata' => array('source' => 'auto-json-lab', 'shape' => 'array_html_fragment', 'trigger' => 'page_load'),
        )
    );
}

function route_auto_idor_account_balance(string $method): void
{
    render_auto_json_trigger(
        'Auto JSON IDOR - Account Balance',
        '/auto/idor/account-balance',
        'idor',
        '/api/json/idor/account-balance',
        'resource.account.user_id',
        'account lookup without owner enforcement',
        array(
            'actor' => array('user_id' => '1'),
            'resource' => array('account' => array('user_id' => '2')),
            'metadata' => array('source' => 'auto-json-lab', 'shape' => 'nested_resource', 'trigger' => 'page_load'),
        )
    );
}

function route_auto_auth_mass_assignment_role(string $method): void
{
    render_auto_json_trigger(
        'Auto JSON Auth - Mass Assignment Role',
        '/auto/auth/mass-assignment-role',
        'auth',
        '/api/json/auth/mass-assignment-role',
        'user.profile.role',
        'unsafe profile update',
        array(
            'user' => array('id' => '1', 'profile' => array('email' => 'alice+mass-auto@example.test', 'role' => 'admin')),
            'metadata' => array('source' => 'auto-json-lab', 'shape' => 'mass_assignment', 'trigger' => 'page_load'),
        )
    );
}

function route_auto_state_transfer_log(string $method): void
{
    render_auto_json_trigger(
        'Auto JSON State - Transfer Log',
        '/auto/state/transfer-log',
        'state_change',
        '/api/json/state/transfer-log',
        'transfer.to_user_id + transfer.amount',
        'INSERT transfer_log without CSRF/auth enforcement',
        array(
            'transfer' => array('from_user_id' => '1', 'to_user_id' => '2', 'amount' => '7.77'),
            'metadata' => array('source' => 'auto-json-lab', 'shape' => 'state_log', 'trigger' => 'page_load'),
        )
    );
}

function route_auto_deserialization_php_object(string $method): void
{
    render_auto_json_trigger(
        'Auto JSON Deserialization - PHP Object',
        '/auto/deserialization/php-object',
        'deserialization',
        '/api/json/deserialization/php-object',
        'payload.serialized',
        'unserialize',
        array(
            'payload' => array('serialized' => 'O:8:"stdClass":1:{s:7:"message";s:17:"auto_deser_obj_ok";}'),
            'metadata' => array('source' => 'auto-json-lab', 'shape' => 'serialized_string', 'trigger' => 'page_load'),
        )
    );
}

function route_auto_cors_reflect_origin_json(string $method): void
{
    render_auto_json_trigger(
        'Auto JSON CORS - Reflect Origin',
        '/auto/cors/reflect-origin-json',
        'cors',
        '/api/json/cors/reflect-origin-json',
        'client.origin',
        'Access-Control-Allow-Origin reflection',
        array(
            'client' => array('origin' => 'https://attacker.example.test'),
            'metadata' => array('source' => 'auto-json-lab', 'shape' => 'header_reflection', 'trigger' => 'page_load'),
        )
    );
}

function route_api_json_rce_argv_array(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }

    $exec = is_array($payload['exec'] ?? null) ? $payload['exec'] : array();
    $binary = (string) ($exec['binary'] ?? 'printf');
    $argv = is_array($exec['argv'] ?? null) ? $exec['argv'] : array('auto_rce_array_ok');
    $parts = array($binary);
    foreach ($argv as $arg) {
        if (is_scalar($arg)) {
            $parts[] = (string) $arg;
        }
    }
    $cmd = implode(' ', $parts);
    $exitCode = 0;
    ob_start();
    @system($cmd, $exitCode);
    $output = (string) ob_get_clean();

    json_response(array(
        'ok' => true,
        'category' => 'rce',
        'sink' => 'system',
        'vulnerable_json_path' => 'exec.binary + exec.argv[]',
        'command' => $cmd,
        'exit_code' => $exitCode,
        'output_preview' => substr($output, 0, 4000),
    ));
}

function route_api_json_rce_workflow_step(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }

    $workflow = is_array($payload['workflow'] ?? null) ? $payload['workflow'] : array();
    $steps = is_array($workflow['steps'] ?? null) ? $workflow['steps'] : array();
    $cmd = 'printf auto_rce_workflow_ok';
    foreach ($steps as $step) {
        if (!is_array($step) || (string) ($step['name'] ?? '') !== 'run') {
            continue;
        }
        $params = is_array($step['params'] ?? null) ? $step['params'] : array();
        $cmd = (string) ($params['command'] ?? $cmd);
    }
    $exitCode = 0;
    ob_start();
    @system($cmd, $exitCode);
    $output = (string) ob_get_clean();

    json_response(array(
        'ok' => true,
        'category' => 'rce',
        'sink' => 'system',
        'vulnerable_json_path' => 'workflow.steps[].params.command',
        'command' => $cmd,
        'exit_code' => $exitCode,
        'output_preview' => substr($output, 0, 4000),
    ));
}

function route_api_json_sqli_search_filter(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }

    $db = db_connect();
    if ($db === null) {
        json_response(array('ok' => false, 'error' => 'database_unavailable'), 503);
        return;
    }
    seed_database($db);
    $search = is_array($payload['search'] ?? null) ? $payload['search'] : array();
    $criteria = is_array($search['criteria'] ?? null) ? $search['criteria'] : array();
    $username = (string) ($criteria['username'] ?? "alice' OR '1'='1");
    $sql = "SELECT id, username, email, role FROM users WHERE username = '$username'";
    json_query_response($db, 'sqli', 'mysqli::query', 'search.criteria.username', $sql);
}

function route_api_json_sqli_sort_clause(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }

    $db = db_connect();
    if ($db === null) {
        json_response(array('ok' => false, 'error' => 'database_unavailable'), 503);
        return;
    }
    seed_database($db);
    $grid = is_array($payload['grid'] ?? null) ? $payload['grid'] : array();
    $sort = is_array($grid['sort'] ?? null) ? $grid['sort'] : array();
    $field = (string) ($sort['field'] ?? 'id');
    $direction = (string) ($sort['direction'] ?? 'DESC');
    $sql = "SELECT id, username, email, role FROM users ORDER BY $field $direction LIMIT 10";
    json_query_response($db, 'sqli', 'mysqli::query ORDER BY concatenation', 'grid.sort.field + grid.sort.direction', $sql);
}

function route_api_json_sqli_batch_lookup(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }

    $db = db_connect();
    if ($db === null) {
        json_response(array('ok' => false, 'error' => 'database_unavailable'), 503);
        return;
    }
    seed_database($db);
    $requests = is_array($payload['requests'] ?? null) ? $payload['requests'] : array(array('id' => '1'), array('id' => '2 OR 1=1'));
    $options = is_array($payload['options'] ?? null) ? $payload['options'] : array();
    $index = (int) ($options['use_index'] ?? 1);
    $request = is_array($requests[$index] ?? null) ? $requests[$index] : array('id' => '1');
    $id = (string) ($request['id'] ?? '1');
    $sql = "SELECT id, username, email, role FROM users WHERE id = $id";
    json_query_response($db, 'sqli', 'mysqli::query', 'requests[options.use_index].id', $sql);
}

function route_api_json_file_lang_include(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }

    $view = is_array($payload['view'] ?? null) ? $payload['view'] : array();
    $locale = (string) ($view['locale'] ?? '..');
    $template = (string) ($view['template'] ?? 'pages/home');
    $cfg = app_config();
    $target = $cfg['lfi_pages_dir'] . '/' . $locale . '/' . $template . '.php';
    ob_start();
    @include $target;
    $included = (string) ob_get_clean();
    $readBody = @file_get_contents($target);

    json_response(array(
        'ok' => true,
        'category' => 'lfi',
        'sink' => 'include+file_get_contents',
        'vulnerable_json_path' => 'view.locale + view.template',
        'target' => $target,
        'included_output_preview' => substr($included, 0, 4000),
        'read_preview' => is_string($readBody) ? substr($readBody, 0, 4000) : null,
        'read_failed' => !is_string($readBody),
    ));
}

function route_api_json_file_path_parts(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }

    $document = is_array($payload['document'] ?? null) ? $payload['document'] : array();
    $pathParts = is_array($document['path_parts'] ?? null) ? $document['path_parts'] : array('home');
    $extension = (string) ($document['extension'] ?? 'php');
    $parts = array();
    foreach ($pathParts as $part) {
        if (is_scalar($part)) {
            $parts[] = (string) $part;
        }
    }
    $cfg = app_config();
    $target = $cfg['lfi_pages_dir'] . '/' . implode('/', $parts) . '.' . $extension;
    $body = @file_get_contents($target);

    json_response(array(
        'ok' => is_string($body),
        'category' => 'lfi',
        'sink' => 'file_get_contents',
        'vulnerable_json_path' => 'document.path_parts[] + document.extension',
        'target' => $target,
        'read_preview' => is_string($body) ? substr($body, 0, 4000) : null,
        'read_failed' => !is_string($body),
    ));
}

function route_api_json_file_write_json(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }

    $artifact = is_array($payload['artifact'] ?? null) ? $payload['artifact'] : array();
    $name = (string) ($artifact['name'] ?? 'auto_json_write.json');
    $content = (string) ($artifact['content'] ?? '{"auto_file_write":"ok"}');
    $safeName = preg_replace('/[^A-Za-z0-9_.-]/', '_', $name);
    $safeName = is_string($safeName) && $safeName !== '' ? $safeName : 'auto_json_write.json';
    $cfg = app_config();
    $dir = $cfg['upload_dir'];
    if (!is_dir($dir)) {
        @mkdir($dir, 0777, true);
    }
    $target = $dir . '/' . $safeName;
    $bytes = @file_put_contents($target, $content);

    json_response(array(
        'ok' => $bytes !== false,
        'category' => 'file_write',
        'sink' => 'file_put_contents',
        'vulnerable_json_path' => 'artifact.name + artifact.content',
        'target' => $target,
        'bytes_written' => $bytes === false ? 0 : $bytes,
        'content_preview' => substr($content, 0, 4000),
        'public_path' => '/uploads/' . $safeName,
    ));
}

function route_api_json_ssrf_webhook_basic(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }

    $url = (string) ($payload['webhook_url'] ?? 'data://text/plain,auto_ssrf_webhook_ok');
    json_fetch_response($url, 'webhook_url');
}

function route_api_json_ssrf_events_callback(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }

    $events = is_array($payload['events'] ?? null) ? $payload['events'] : array();
    $url = 'data://text/plain,auto_ssrf_event_ok';
    foreach ($events as $event) {
        if (!is_array($event) || (string) ($event['type'] ?? '') !== 'notify') {
            continue;
        }
        $delivery = is_array($event['delivery'] ?? null) ? $event['delivery'] : array();
        $callback = is_array($delivery['callback'] ?? null) ? $delivery['callback'] : array();
        $url = (string) ($callback['href'] ?? $url);
    }
    json_fetch_response($url, 'events[].delivery.callback.href');
}

function route_api_json_xss_profile_card(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }

    $profile = is_array($payload['profile'] ?? null) ? $payload['profile'] : array();
    $displayName = (string) ($profile['display_name'] ?? '<img src=x onerror=alert(1)>');
    $bio = (string) ($profile['bio'] ?? 'auto profile card');
    $html = '<article class="profile-card"><h2>' . $displayName . '</h2><p>' . $bio . '</p></article>';

    json_response(array(
        'ok' => true,
        'category' => 'xss',
        'sink' => 'HTML template concatenation',
        'vulnerable_json_path' => 'profile.display_name + profile.bio',
        'html_preview' => substr($html, 0, 4000),
    ));
}

function route_api_json_xss_dom_fragment(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }

    $widgets = is_array($payload['widgets'] ?? null) ? $payload['widgets'] : array(array('slot' => 'summary', 'html' => '<svg/onload=alert(1)>'));
    $widget = is_array($widgets[0] ?? null) ? $widgets[0] : array('slot' => 'summary', 'html' => '<svg/onload=alert(1)>');
    $slot = (string) ($widget['slot'] ?? 'summary');
    $html = (string) ($widget['html'] ?? '<svg/onload=alert(1)>');
    $domContract = "document.querySelector('[data-slot=\"" . $slot . "\"]').innerHTML = payload.widgets[0].html";

    json_response(array(
        'ok' => true,
        'category' => 'xss',
        'sink' => 'client DOM innerHTML contract',
        'vulnerable_json_path' => 'widgets[0].html',
        'slot' => $slot,
        'dom_contract' => $domContract,
        'html_fragment' => $html,
    ));
}

function route_api_json_idor_account_balance(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }

    $db = db_connect();
    if ($db === null) {
        json_response(array('ok' => false, 'error' => 'database_unavailable'), 503);
        return;
    }
    seed_database($db);
    $actor = is_array($payload['actor'] ?? null) ? $payload['actor'] : array();
    $resource = is_array($payload['resource'] ?? null) ? $payload['resource'] : array();
    $account = is_array($resource['account'] ?? null) ? $resource['account'] : array();
    $actorUserId = (string) ($actor['user_id'] ?? '1');
    $targetUserId = (string) ($account['user_id'] ?? '2');
    $sql = "SELECT user_id, balance FROM accounts WHERE user_id = $targetUserId";
    $res = $db->query($sql);
    if ($res === false) {
        json_response(array('ok' => false, 'category' => 'idor', 'sink' => 'mysqli::query', 'vulnerable_json_path' => 'resource.account.user_id', 'sql' => $sql, 'db_error' => $db->error));
        return;
    }
    $rows = array();
    if ($res instanceof mysqli_result) {
        while ($row = $res->fetch_assoc()) {
            $rows[] = $row;
        }
    }
    json_response(array(
        'ok' => true,
        'category' => 'idor',
        'sink' => 'account lookup without owner enforcement',
        'vulnerable_json_path' => 'resource.account.user_id',
        'actor_user_id' => $actorUserId,
        'sql' => $sql,
        'rows' => $rows,
    ));
}

function route_api_json_auth_mass_assignment_role(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }

    $db = db_connect();
    if ($db === null) {
        json_response(array('ok' => false, 'error' => 'database_unavailable'), 503);
        return;
    }
    seed_database($db);
    $user = is_array($payload['user'] ?? null) ? $payload['user'] : array();
    $profile = is_array($user['profile'] ?? null) ? $user['profile'] : array();
    $id = (string) ($user['id'] ?? '1');
    $email = (string) ($profile['email'] ?? 'alice+mass-auto@example.test');
    $role = (string) ($profile['role'] ?? 'admin');
    $sql = "UPDATE users SET email='" . $db->real_escape_string($email) . "', role='" . $db->real_escape_string($role) . "' WHERE id=$id";
    $ok = $db->query($sql);
    $affectedRows = $db->affected_rows;
    $res = $db->query("SELECT id, username, email, role FROM users WHERE id=$id");
    $row = $res instanceof mysqli_result ? $res->fetch_assoc() : null;

    json_response(array(
        'ok' => $ok !== false,
        'category' => 'auth',
        'sink' => 'unsafe mass assignment update',
        'vulnerable_json_path' => 'user.profile.role',
        'sql' => $sql,
        'affected_rows' => $affectedRows,
        'updated_user' => $row,
        'db_error' => $ok === false ? $db->error : null,
    ));
}

function route_api_json_state_transfer_log(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }

    $db = db_connect();
    if ($db === null) {
        json_response(array('ok' => false, 'error' => 'database_unavailable'), 503);
        return;
    }
    seed_database($db);
    $transfer = is_array($payload['transfer'] ?? null) ? $payload['transfer'] : array();
    $from = (string) ($transfer['from_user_id'] ?? '1');
    $to = (string) ($transfer['to_user_id'] ?? '2');
    $amount = (string) ($transfer['amount'] ?? '7.77');
    $db->query("DELETE FROM transfer_log WHERE from_user_id=1 AND to_user_id=2 AND amount=7.77");
    $sql = "INSERT INTO transfer_log(from_user_id,to_user_id,amount,created_at) VALUES($from,$to,$amount,NOW())";
    $ok = $db->query($sql);

    json_response(array(
        'ok' => $ok !== false,
        'category' => 'state_change',
        'sink' => 'INSERT transfer_log without CSRF/auth enforcement',
        'vulnerable_json_path' => 'transfer.from_user_id + transfer.to_user_id + transfer.amount',
        'sql' => $sql,
        'transfer_log_id' => $ok === false ? 0 : (int) $db->insert_id,
        'db_error' => $ok === false ? $db->error : null,
    ));
}

function route_api_json_deserialization_php_object(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }

    $body = is_array($payload['payload'] ?? null) ? $payload['payload'] : array();
    $serialized = (string) ($body['serialized'] ?? 'O:8:"stdClass":1:{s:7:"message";s:17:"auto_deser_obj_ok";}');
    $value = @unserialize($serialized);

    json_response(array(
        'ok' => $value !== false || $serialized === 'b:0;',
        'category' => 'deserialization',
        'sink' => 'unserialize',
        'vulnerable_json_path' => 'payload.serialized',
        'serialized_preview' => substr($serialized, 0, 4000),
        'result_type' => is_object($value) ? get_class($value) : gettype($value),
        'result_preview' => substr(print_r($value, true), 0, 4000),
    ));
}

function route_api_json_cors_reflect_origin_json(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }

    $client = is_array($payload['client'] ?? null) ? $payload['client'] : array();
    $origin = (string) ($client['origin'] ?? 'https://attacker.example.test');

    json_response(array(
        'ok' => true,
        'category' => 'cors',
        'sink' => 'Access-Control-Allow-Origin reflection',
        'vulnerable_json_path' => 'client.origin',
        'reflected_origin' => $origin,
    ), 200, array(
        'Access-Control-Allow-Origin' => $origin,
        'Access-Control-Allow-Credentials' => 'true',
    ));
}

function route_auto_rce_template_eval(string $method): void
{
    render_auto_json_trigger('Auto JSON RCE - Template Eval', '/auto/rce/template-eval', 'rce', '/api/json/rce/template-eval', 'template.php', 'eval($php)', array(
        'template' => array('engine' => 'php', 'php' => 'echo "auto_eval_template_ok";'),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'template_object', 'trigger' => 'page_load'),
    ));
}

function route_auto_rce_env_chain(string $method): void
{
    render_auto_json_trigger('Auto JSON RCE - Env Chain', '/auto/rce/env-chain', 'rce', '/api/json/rce/env-chain', 'runtime.env.COMMAND', 'shell_exec($env["COMMAND"])', array(
        'runtime' => array('env' => array('COMMAND' => 'printf auto_rce_env_ok'), 'mode' => 'diagnostic'),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'metadata_disguised', 'trigger' => 'page_load'),
    ));
}

function route_auto_sqli_graphql_user(string $method): void
{
    render_auto_json_trigger('Auto JSON SQLi - GraphQL User', '/auto/sqli/graphql-user', 'sqli', '/api/json/sqli/graphql-user', 'operation.variables.userId', 'mysqli::query', array(
        'operation' => array('name' => 'UserLookup', 'variables' => array('userId' => '1 OR 1=1')),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'graphql_like', 'trigger' => 'page_load'),
    ));
}

function route_auto_sqli_report_range(string $method): void
{
    render_auto_json_trigger('Auto JSON SQLi - Report Range', '/auto/sqli/report-range', 'sqli', '/api/json/sqli/report-range', 'report.filters.range.end', 'mysqli::query', array(
        'report' => array('name' => 'orders', 'filters' => array('range' => array('start' => 'paid', 'end' => "paid' OR '1'='1"))),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'report_filter', 'trigger' => 'page_load'),
    ));
}

function route_auto_sqli_ids_array(string $method): void
{
    render_auto_json_trigger('Auto JSON SQLi - IDs Array', '/auto/sqli/ids-array', 'sqli', '/api/json/sqli/ids-array', 'ids[]', 'mysqli::query IN clause', array(
        'ids' => array('1) OR 1=1 -- '),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'array_in_clause', 'trigger' => 'page_load'),
    ));
}

function route_auto_sqli_json_operator(string $method): void
{
    render_auto_json_trigger('Auto JSON SQLi - JSON Operator', '/auto/sqli/json-operator', 'sqli', '/api/json/sqli/json-operator', 'filters[0].field + filters[0].operator + filters[0].value', 'mysqli::query dynamic predicate', array(
        'filters' => array(array('field' => 'username', 'operator' => '=', 'value' => "alice' OR '1'='1")),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'dynamic_operator', 'trigger' => 'page_load'),
    ));
}

function route_auto_file_base64_read(string $method): void
{
    render_auto_json_trigger('Auto JSON File - Base64 Read', '/auto/file/base64-read', 'lfi', '/api/json/file/base64-read', 'blob.encoded_path', 'base64_decode + file_get_contents', array(
        'blob' => array('encoding' => 'base64', 'encoded_path' => 'aG9tZS5waHA='),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'encoded_path', 'trigger' => 'page_load'),
    ));
}

function route_auto_file_theme_asset(string $method): void
{
    render_auto_json_trigger('Auto JSON File - Theme Asset', '/auto/file/theme-asset', 'lfi', '/api/json/file/theme-asset', 'ui.theme.name + ui.theme.asset', 'file_get_contents', array(
        'ui' => array('theme' => array('name' => '..', 'asset' => 'pages/help.php')),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'theme_asset', 'trigger' => 'page_load'),
    ));
}

function route_auto_file_temp_cleanup(string $method): void
{
    render_auto_json_trigger('Auto JSON File - Temp Cleanup', '/auto/file/temp-cleanup', 'file_delete', '/api/json/file/temp-cleanup', 'cleanup.targets[0]', 'unlink', array(
        'cleanup' => array('targets' => array('auto_cleanup_marker.txt')),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'cleanup_array', 'trigger' => 'page_load'),
    ));
}

function route_auto_ssrf_oembed_url(string $method): void
{
    render_auto_json_trigger('Auto JSON SSRF - oEmbed URL', '/auto/ssrf/oembed-url', 'ssrf', '/api/json/ssrf/oembed-url', 'preview.oembed.endpoint', 'file_get_contents', array(
        'preview' => array('oembed' => array('endpoint' => 'data://text/plain,auto_ssrf_oembed_ok')),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'nested_endpoint', 'trigger' => 'page_load'),
    ));
}

function route_auto_ssrf_openapi_server(string $method): void
{
    render_auto_json_trigger('Auto JSON SSRF - OpenAPI Server', '/auto/ssrf/openapi-server', 'ssrf', '/api/json/ssrf/openapi-server', 'spec.servers[0].url', 'file_get_contents', array(
        'spec' => array('servers' => array(array('url' => 'data://text/plain,auto_ssrf_openapi_ok'))),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'openapi_servers', 'trigger' => 'page_load'),
    ));
}

function route_auto_ssrf_avatar_proxy(string $method): void
{
    render_auto_json_trigger('Auto JSON SSRF - Avatar Proxy', '/auto/ssrf/avatar-proxy', 'ssrf', '/api/json/ssrf/avatar-proxy', 'users[0].avatar.url', 'file_get_contents', array(
        'users' => array(array('id' => 1, 'avatar' => array('url' => 'data://text/plain,auto_ssrf_avatar_ok'))),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'array_object_url', 'trigger' => 'page_load'),
    ));
}

function route_auto_xss_markdown_preview(string $method): void
{
    render_auto_json_trigger('Auto JSON XSS - Markdown Preview', '/auto/xss/markdown-preview', 'xss', '/api/json/xss/markdown-preview', 'markdown.body', 'unsafe markdown preview', array(
        'markdown' => array('body' => '# Preview\n<img src=x onerror=alert(1)>'),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'markdown', 'trigger' => 'page_load'),
    ));
}

function route_auto_xss_svg_avatar(string $method): void
{
    render_auto_json_trigger('Auto JSON XSS - SVG Avatar', '/auto/xss/svg-avatar', 'xss', '/api/json/xss/svg-avatar', 'asset.svg', 'SVG stored/render preview', array(
        'asset' => array('filename' => 'auto-avatar.svg', 'svg' => '<svg onload="alert(1)" xmlns="http://www.w3.org/2000/svg"></svg>'),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'svg_asset', 'trigger' => 'page_load'),
    ));
}

function route_auto_xss_json_error_message(string $method): void
{
    render_auto_json_trigger('Auto JSON XSS - JSON Error Message', '/auto/xss/json-error-message', 'xss', '/api/json/xss/json-error-message', 'errors[0].message', 'error banner HTML concatenation', array(
        'errors' => array(array('code' => 'AUTO', 'message' => '<marquee onstart=alert(1)>auto error</marquee>')),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'error_array', 'trigger' => 'page_load'),
    ));
}

function route_auto_idor_invoice_export(string $method): void
{
    render_auto_json_trigger('Auto JSON IDOR - Invoice Export', '/auto/idor/invoice-export', 'idor', '/api/json/idor/invoice-export', 'export.invoice_id', 'invoice/order export without owner enforcement', array(
        'actor' => array('user_id' => '1'),
        'export' => array('invoice_id' => '2', 'format' => 'json'),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'export_object', 'trigger' => 'page_load'),
    ));
}

function route_auto_idor_team_settings(string $method): void
{
    render_auto_json_trigger('Auto JSON IDOR - Team Settings', '/auto/idor/team-settings', 'idor', '/api/json/idor/team-settings', 'team.members[0].user_id', 'team settings lookup without membership enforcement', array(
        'actor' => array('user_id' => '1'),
        'team' => array('members' => array(array('user_id' => '3'))),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'team_members_array', 'trigger' => 'page_load'),
    ));
}

function route_auto_auth_debug_impersonate(string $method): void
{
    render_auto_json_trigger('Auto JSON Auth - Debug Impersonate', '/auto/auth/debug-impersonate', 'auth', '/api/json/auth/debug-impersonate', 'debug.impersonate.user_id', 'session user assignment without authorization', array(
        'debug' => array('impersonate' => array('user_id' => '3')),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'debug_object', 'trigger' => 'page_load'),
    ));
}

function route_auto_auth_password_reset_token(string $method): void
{
    render_auto_json_trigger('Auto JSON Auth - Password Reset Token', '/auto/auth/password-reset-token', 'auth', '/api/json/auth/password-reset-token', 'account.email', 'predictable token generation and disclosure', array(
        'account' => array('email' => 'alice@example.test'),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'token_request', 'trigger' => 'page_load'),
    ));
}

function route_auto_state_feature_flag(string $method): void
{
    render_auto_json_trigger('Auto JSON State - Feature Flag', '/auto/state/feature-flag', 'state_change', '/api/json/state/feature-flag', 'flags[0].name + flags[0].enabled', 'file_put_contents feature flag state', array(
        'tenant' => array('id' => 'lab'),
        'flags' => array(array('name' => 'admin_console', 'enabled' => true)),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'flags_array', 'trigger' => 'page_load'),
    ));
}

function route_auto_state_cart_price(string $method): void
{
    render_auto_json_trigger('Auto JSON State - Cart Price', '/auto/state/cart-price', 'state_change', '/api/json/state/cart-price', 'cart.items[0].unit_price', 'server trusts client-supplied price', array(
        'cart' => array('items' => array(array('sku' => 'LAB-001', 'qty' => 2, 'unit_price' => 0.01))),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'cart_array', 'trigger' => 'page_load'),
    ));
}

function route_auto_deserialization_base64_object(string $method): void
{
    render_auto_json_trigger('Auto JSON Deserialization - Base64 Object', '/auto/deserialization/base64-object', 'deserialization', '/api/json/deserialization/base64-object', 'payload.b64', 'base64_decode + unserialize', array(
        'payload' => array('b64' => base64_encode('O:8:"stdClass":1:{s:7:"message";s:17:"auto_deser_b64_ok";}')),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'encoded_serialized_object', 'trigger' => 'page_load'),
    ));
}

function route_auto_redirect_json_next(string $method): void
{
    render_auto_json_trigger('Auto JSON Redirect - JSON Next', '/auto/redirect/json-next', 'open_redirect', '/api/json/redirect/json-next', 'navigation.next', 'Location header from JSON', array(
        'navigation' => array('next' => 'https://example.org/auto-json-redirect'),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'navigation_object', 'trigger' => 'page_load'),
    ));
}

function route_auto_cors_preflight_cache(string $method): void
{
    render_auto_json_trigger('Auto JSON CORS - Preflight Cache', '/auto/cors/preflight-cache', 'cors', '/api/json/cors/preflight-cache', 'policy.origins[0] + policy.headers[]', 'CORS preflight policy reflection', array(
        'policy' => array('origins' => array('https://evil-cache.example.test'), 'headers' => array('X-Pentest-Token', 'Authorization'), 'max_age' => 86400),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'cors_policy', 'trigger' => 'page_load'),
    ));
}

function route_api_json_rce_template_eval(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $template = is_array($payload['template'] ?? null) ? $payload['template'] : array();
    $php = (string) ($template['php'] ?? 'echo "auto_eval_template_ok";');
    ob_start();
    @eval($php);
    $output = (string) ob_get_clean();
    json_response(array('ok' => true, 'category' => 'rce', 'sink' => 'eval', 'vulnerable_json_path' => 'template.php', 'code_preview' => substr($php, 0, 4000), 'output_preview' => substr($output, 0, 4000)));
}

function route_api_json_rce_env_chain(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $runtime = is_array($payload['runtime'] ?? null) ? $payload['runtime'] : array();
    $env = is_array($runtime['env'] ?? null) ? $runtime['env'] : array();
    $cmd = (string) ($env['COMMAND'] ?? 'printf auto_rce_env_ok');
    $output = @shell_exec($cmd);
    json_response(array('ok' => true, 'category' => 'rce', 'sink' => 'shell_exec', 'vulnerable_json_path' => 'runtime.env.COMMAND', 'command' => $cmd, 'output_preview' => substr((string) $output, 0, 4000)));
}

function route_api_json_sqli_graphql_user(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $db = db_connect();
    if ($db === null) {
        json_response(array('ok' => false, 'error' => 'database_unavailable'), 503);
        return;
    }
    seed_database($db);
    $operation = is_array($payload['operation'] ?? null) ? $payload['operation'] : array();
    $variables = is_array($operation['variables'] ?? null) ? $operation['variables'] : array();
    $id = (string) ($variables['userId'] ?? '1 OR 1=1');
    json_query_response($db, 'sqli', 'mysqli::query', 'operation.variables.userId', "SELECT id, username, email, role FROM users WHERE id = $id");
}

function route_api_json_sqli_report_range(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $db = db_connect();
    if ($db === null) {
        json_response(array('ok' => false, 'error' => 'database_unavailable'), 503);
        return;
    }
    seed_database($db);
    $report = is_array($payload['report'] ?? null) ? $payload['report'] : array();
    $filters = is_array($report['filters'] ?? null) ? $report['filters'] : array();
    $range = is_array($filters['range'] ?? null) ? $filters['range'] : array();
    $end = (string) ($range['end'] ?? "paid' OR '1'='1");
    json_query_response($db, 'sqli', 'mysqli::query', 'report.filters.range.end', "SELECT id, owner_user_id, item_name, status FROM orders WHERE status = '$end'");
}

function route_api_json_sqli_ids_array(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $db = db_connect();
    if ($db === null) {
        json_response(array('ok' => false, 'error' => 'database_unavailable'), 503);
        return;
    }
    seed_database($db);
    $ids = is_array($payload['ids'] ?? null) ? $payload['ids'] : array('1) OR 1=1 -- ');
    $parts = array();
    foreach ($ids as $id) {
        if (is_scalar($id)) {
            $parts[] = (string) $id;
        }
    }
    json_query_response($db, 'sqli', 'mysqli::query IN clause', 'ids[]', 'SELECT id, username, email, role FROM users WHERE id IN (' . implode(',', $parts) . ')');
}

function route_api_json_sqli_json_operator(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $db = db_connect();
    if ($db === null) {
        json_response(array('ok' => false, 'error' => 'database_unavailable'), 503);
        return;
    }
    seed_database($db);
    $filters = is_array($payload['filters'] ?? null) ? $payload['filters'] : array();
    $filter = is_array($filters[0] ?? null) ? $filters[0] : array('field' => 'username', 'operator' => '=', 'value' => "alice' OR '1'='1");
    $field = (string) ($filter['field'] ?? 'username');
    $operator = (string) ($filter['operator'] ?? '=');
    $value = (string) ($filter['value'] ?? "alice' OR '1'='1");
    json_query_response($db, 'sqli', 'mysqli::query dynamic predicate', 'filters[0].field + filters[0].operator + filters[0].value', "SELECT id, username, email, role FROM users WHERE $field $operator '$value'");
}

function route_api_json_file_base64_read(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $blob = is_array($payload['blob'] ?? null) ? $payload['blob'] : array();
    $encoded = (string) ($blob['encoded_path'] ?? 'aG9tZS5waHA=');
    $decoded = base64_decode($encoded, true);
    $decoded = is_string($decoded) ? $decoded : 'home.php';
    $cfg = app_config();
    $target = $cfg['lfi_pages_dir'] . '/' . $decoded;
    $body = @file_get_contents($target);
    json_response(array('ok' => is_string($body), 'category' => 'lfi', 'sink' => 'base64_decode+file_get_contents', 'vulnerable_json_path' => 'blob.encoded_path', 'decoded_path' => $decoded, 'target' => $target, 'read_preview' => is_string($body) ? substr($body, 0, 4000) : null, 'read_failed' => !is_string($body)));
}

function route_api_json_file_theme_asset(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $ui = is_array($payload['ui'] ?? null) ? $payload['ui'] : array();
    $theme = is_array($ui['theme'] ?? null) ? $ui['theme'] : array();
    $name = (string) ($theme['name'] ?? '..');
    $asset = (string) ($theme['asset'] ?? 'pages/help.php');
    $cfg = app_config();
    $target = $cfg['lfi_pages_dir'] . '/' . $name . '/' . $asset;
    $body = @file_get_contents($target);
    json_response(array('ok' => is_string($body), 'category' => 'lfi', 'sink' => 'file_get_contents', 'vulnerable_json_path' => 'ui.theme.name + ui.theme.asset', 'target' => $target, 'read_preview' => is_string($body) ? substr($body, 0, 4000) : null, 'read_failed' => !is_string($body)));
}

function route_api_json_file_temp_cleanup(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $cleanup = is_array($payload['cleanup'] ?? null) ? $payload['cleanup'] : array();
    $targets = is_array($cleanup['targets'] ?? null) ? $cleanup['targets'] : array('auto_cleanup_marker.txt');
    $targetName = is_scalar($targets[0] ?? null) ? (string) $targets[0] : 'auto_cleanup_marker.txt';
    $cfg = app_config();
    if (!is_dir($cfg['upload_dir'])) {
        @mkdir($cfg['upload_dir'], 0777, true);
    }
    $target = $cfg['upload_dir'] . '/' . $targetName;
    @file_put_contents($target, 'auto_cleanup_marker');
    $deleted = @unlink($target);
    json_response(array('ok' => $deleted, 'category' => 'file_delete', 'sink' => 'unlink', 'vulnerable_json_path' => 'cleanup.targets[0]', 'target' => $target, 'deleted' => $deleted));
}

function route_api_json_ssrf_oembed_url(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $preview = is_array($payload['preview'] ?? null) ? $payload['preview'] : array();
    $oembed = is_array($preview['oembed'] ?? null) ? $preview['oembed'] : array();
    json_fetch_response((string) ($oembed['endpoint'] ?? 'data://text/plain,auto_ssrf_oembed_ok'), 'preview.oembed.endpoint');
}

function route_api_json_ssrf_openapi_server(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $spec = is_array($payload['spec'] ?? null) ? $payload['spec'] : array();
    $servers = is_array($spec['servers'] ?? null) ? $spec['servers'] : array(array('url' => 'data://text/plain,auto_ssrf_openapi_ok'));
    $server = is_array($servers[0] ?? null) ? $servers[0] : array();
    json_fetch_response((string) ($server['url'] ?? 'data://text/plain,auto_ssrf_openapi_ok'), 'spec.servers[0].url');
}

function route_api_json_ssrf_avatar_proxy(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $users = is_array($payload['users'] ?? null) ? $payload['users'] : array();
    $user = is_array($users[0] ?? null) ? $users[0] : array();
    $avatar = is_array($user['avatar'] ?? null) ? $user['avatar'] : array();
    json_fetch_response((string) ($avatar['url'] ?? 'data://text/plain,auto_ssrf_avatar_ok'), 'users[0].avatar.url');
}

function route_api_json_xss_markdown_preview(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $markdown = is_array($payload['markdown'] ?? null) ? $payload['markdown'] : array();
    $body = (string) ($markdown['body'] ?? "# Preview\n<img src=x onerror=alert(1)>");
    $html = '<div class="markdown-preview">' . str_replace("\n", '<br>', $body) . '</div>';
    json_response(array('ok' => true, 'category' => 'xss', 'sink' => 'unsafe markdown preview', 'vulnerable_json_path' => 'markdown.body', 'html_preview' => substr($html, 0, 4000)));
}

function route_api_json_xss_svg_avatar(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $asset = is_array($payload['asset'] ?? null) ? $payload['asset'] : array();
    $filename = (string) ($asset['filename'] ?? 'auto-avatar.svg');
    $svg = (string) ($asset['svg'] ?? '<svg onload="alert(1)" xmlns="http://www.w3.org/2000/svg"></svg>');
    json_response(array('ok' => true, 'category' => 'xss', 'sink' => 'SVG stored/render preview', 'vulnerable_json_path' => 'asset.svg', 'filename' => $filename, 'svg_preview' => substr($svg, 0, 4000)));
}

function route_api_json_xss_json_error_message(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $errors = is_array($payload['errors'] ?? null) ? $payload['errors'] : array();
    $error = is_array($errors[0] ?? null) ? $errors[0] : array();
    $message = (string) ($error['message'] ?? '<marquee onstart=alert(1)>auto error</marquee>');
    $html = '<div class="error-banner">' . $message . '</div>';
    json_response(array('ok' => true, 'category' => 'xss', 'sink' => 'error banner HTML concatenation', 'vulnerable_json_path' => 'errors[0].message', 'html_preview' => substr($html, 0, 4000)));
}

function route_api_json_idor_invoice_export(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $db = db_connect();
    if ($db === null) {
        json_response(array('ok' => false, 'error' => 'database_unavailable'), 503);
        return;
    }
    seed_database($db);
    $actor = is_array($payload['actor'] ?? null) ? $payload['actor'] : array();
    $export = is_array($payload['export'] ?? null) ? $payload['export'] : array();
    $actorId = (string) ($actor['user_id'] ?? '1');
    $invoiceId = (string) ($export['invoice_id'] ?? '2');
    $sql = "SELECT id AS invoice_id, owner_user_id, item_name, total_amount, status FROM orders WHERE id = $invoiceId";
    $res = $db->query($sql);
    $rows = array();
    if ($res instanceof mysqli_result) {
        while ($row = $res->fetch_assoc()) {
            $rows[] = $row;
        }
    }
    json_response(array('ok' => $res !== false, 'category' => 'idor', 'sink' => 'invoice/order export without owner enforcement', 'vulnerable_json_path' => 'export.invoice_id', 'actor_user_id' => $actorId, 'sql' => $sql, 'rows' => $rows, 'db_error' => $res === false ? $db->error : null));
}

function route_api_json_idor_team_settings(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $db = db_connect();
    if ($db === null) {
        json_response(array('ok' => false, 'error' => 'database_unavailable'), 503);
        return;
    }
    seed_database($db);
    $team = is_array($payload['team'] ?? null) ? $payload['team'] : array();
    $members = is_array($team['members'] ?? null) ? $team['members'] : array(array('user_id' => '3'));
    $member = is_array($members[0] ?? null) ? $members[0] : array();
    $userId = (string) ($member['user_id'] ?? '3');
    json_query_response($db, 'idor', 'team settings lookup without membership enforcement', 'team.members[0].user_id', "SELECT id, username, email, role FROM users WHERE id = $userId");
}

function route_api_json_auth_debug_impersonate(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $db = db_connect();
    if ($db === null) {
        json_response(array('ok' => false, 'error' => 'database_unavailable'), 503);
        return;
    }
    seed_database($db);
    $debug = is_array($payload['debug'] ?? null) ? $payload['debug'] : array();
    $impersonate = is_array($debug['impersonate'] ?? null) ? $debug['impersonate'] : array();
    $userId = (string) ($impersonate['user_id'] ?? '3');
    $res = $db->query("SELECT id, username, role, email FROM users WHERE id=$userId");
    $row = $res instanceof mysqli_result ? $res->fetch_assoc() : null;
    if (is_array($row)) {
        $_SESSION['user'] = array('id' => (int) $row['id'], 'username' => (string) $row['username'], 'role' => (string) $row['role'], 'email' => (string) $row['email']);
    }
    json_response(array('ok' => is_array($row), 'category' => 'auth', 'sink' => 'session user assignment without authorization', 'vulnerable_json_path' => 'debug.impersonate.user_id', 'impersonated_user' => $row, 'session_user' => $_SESSION['user'] ?? null));
}

function route_api_json_auth_password_reset_token(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $account = is_array($payload['account'] ?? null) ? $payload['account'] : array();
    $email = (string) ($account['email'] ?? 'alice@example.test');
    $token = substr(sha1('reset:' . strtolower($email)), 0, 16);
    json_response(array('ok' => true, 'category' => 'auth', 'sink' => 'predictable token generation and disclosure', 'vulnerable_json_path' => 'account.email', 'email' => $email, 'reset_token' => $token));
}

function route_api_json_state_feature_flag(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $cfg = app_config();
    if (!is_dir($cfg['upload_dir'])) {
        @mkdir($cfg['upload_dir'], 0777, true);
    }
    $target = $cfg['upload_dir'] . '/auto_feature_flags.json';
    $bytes = @file_put_contents($target, json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    json_response(array('ok' => $bytes !== false, 'category' => 'state_change', 'sink' => 'file_put_contents feature flag state', 'vulnerable_json_path' => 'flags[0].name + flags[0].enabled', 'target' => $target, 'bytes_written' => $bytes === false ? 0 : $bytes, 'public_path' => '/uploads/auto_feature_flags.json'));
}

function route_api_json_state_cart_price(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $cart = is_array($payload['cart'] ?? null) ? $payload['cart'] : array();
    $items = is_array($cart['items'] ?? null) ? $cart['items'] : array();
    $total = 0.0;
    foreach ($items as $item) {
        if (!is_array($item)) {
            continue;
        }
        $total += (float) ($item['qty'] ?? 1) * (float) ($item['unit_price'] ?? 0);
    }
    $_SESSION['cart_total'] = $total;
    json_response(array('ok' => true, 'category' => 'state_change', 'sink' => 'server trusts client-supplied price', 'vulnerable_json_path' => 'cart.items[].unit_price', 'trusted_total' => number_format($total, 2, '.', ''), 'session_cart_total' => $_SESSION['cart_total']));
}

function route_api_json_deserialization_base64_object(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $body = is_array($payload['payload'] ?? null) ? $payload['payload'] : array();
    $b64 = (string) ($body['b64'] ?? base64_encode('O:8:"stdClass":1:{s:7:"message";s:17:"auto_deser_b64_ok";}'));
    $serialized = base64_decode($b64, true);
    $serialized = is_string($serialized) ? $serialized : '';
    $value = @unserialize($serialized);
    json_response(array('ok' => $value !== false || $serialized === 'b:0;', 'category' => 'deserialization', 'sink' => 'base64_decode+unserialize', 'vulnerable_json_path' => 'payload.b64', 'serialized_preview' => substr($serialized, 0, 4000), 'result_type' => is_object($value) ? get_class($value) : gettype($value), 'result_preview' => substr(print_r($value, true), 0, 4000)));
}

function route_api_json_redirect_json_next(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $navigation = is_array($payload['navigation'] ?? null) ? $payload['navigation'] : array();
    $next = (string) ($navigation['next'] ?? 'https://example.org/auto-json-redirect');
    json_response(array('ok' => true, 'category' => 'open_redirect', 'sink' => 'Location header from JSON', 'vulnerable_json_path' => 'navigation.next', 'redirect_target' => $next), 302, array('Location' => $next));
}

function route_api_json_cors_preflight_cache(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $policy = is_array($payload['policy'] ?? null) ? $payload['policy'] : array();
    $origins = is_array($policy['origins'] ?? null) ? $policy['origins'] : array('https://evil-cache.example.test');
    $headers = is_array($policy['headers'] ?? null) ? $policy['headers'] : array('X-Pentest-Token', 'Authorization');
    $origin = is_scalar($origins[0] ?? null) ? (string) $origins[0] : 'https://evil-cache.example.test';
    $allowedHeaders = array();
    foreach ($headers as $headerName) {
        if (is_scalar($headerName)) {
            $allowedHeaders[] = (string) $headerName;
        }
    }
    $maxAge = (string) ($policy['max_age'] ?? '86400');
    json_response(array('ok' => true, 'category' => 'cors', 'sink' => 'CORS preflight policy reflection', 'vulnerable_json_path' => 'policy.origins[0] + policy.headers[]', 'reflected_origin' => $origin, 'allowed_headers' => $allowedHeaders, 'max_age' => $maxAge), 200, array(
        'Access-Control-Allow-Origin' => $origin,
        'Access-Control-Allow-Credentials' => 'true',
        'Access-Control-Allow-Headers' => implode(', ', $allowedHeaders),
        'Access-Control-Max-Age' => $maxAge,
    ));
}

function route_api_json_ssrf_fetch(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }

    $request = is_array($payload['request'] ?? null) ? $payload['request'] : array();
    $options = is_array($payload['options'] ?? null) ? $payload['options'] : array();
    $url = (string) ($request['url'] ?? 'data://text/plain,auto_ssrf_fetch_ok');
    $timeout = (float) ($options['timeout_seconds'] ?? 4);
    if ($timeout <= 0 || $timeout > 10) {
        $timeout = 4;
    }

    $context = stream_context_create(array(
        'http' => array('timeout' => $timeout, 'ignore_errors' => true),
        'ftp' => array('timeout' => $timeout),
    ));
    $body = @file_get_contents($url, false, $context);
    $headers = isset($http_response_header) && is_array($http_response_header) ? $http_response_header : array();

    json_response(array(
        'ok' => is_string($body),
        'category' => 'ssrf',
        'sink' => 'file_get_contents',
        'url' => $url,
        'timeout_seconds' => $timeout,
        'response_headers' => array_slice($headers, 0, 10),
        'body_preview' => is_string($body) ? substr($body, 0, 4000) : null,
        'fetch_failed' => !is_string($body),
    ));
}

function route_api_json_xss_stored_comment(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }

    $db = db_connect();
    if ($db === null) {
        json_response(array('ok' => false, 'error' => 'database_unavailable'), 503);
        return;
    }

    seed_database($db);
    $actor = is_array($payload['actor'] ?? null) ? $payload['actor'] : array();
    $comment = is_array($payload['comment'] ?? null) ? $payload['comment'] : array();
    $userId = (int) ($actor['user_id'] ?? 1);
    $body = (string) ($comment['body'] ?? "AUTO_JSON_XSS:<svg/onload=alert('auto-json-xss')>");

    $db->query("DELETE FROM comments WHERE body LIKE 'AUTO_JSON_XSS:%'");
    $sql = "INSERT INTO comments(user_id, body, created_at) VALUES ($userId, '" . $db->real_escape_string($body) . "', NOW())";
    $ok = $db->query($sql);
    $commentId = $ok === false ? 0 : (int) $db->insert_id;

    json_response(array(
        'ok' => $ok !== false,
        'category' => 'xss',
        'sink' => 'stored_comment_render',
        'sql' => $sql,
        'comment_id' => $commentId,
        'user_id' => $userId,
        'body_preview' => substr($body, 0, 4000),
        'view_path' => '/xss/stored',
        'db_error' => $ok === false ? $db->error : null,
    ));
}

function route_api_json_idor_order(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }

    $db = db_connect();
    if ($db === null) {
        json_response(array('ok' => false, 'error' => 'database_unavailable'), 503);
        return;
    }

    seed_database($db);
    $actor = is_array($payload['actor'] ?? null) ? $payload['actor'] : array();
    $lookup = is_array($payload['lookup'] ?? null) ? $payload['lookup'] : array();
    $options = is_array($payload['options'] ?? null) ? $payload['options'] : array();
    $actorUserId = (string) ($actor['user_id'] ?? '1');
    $orderId = (string) ($lookup['order_id'] ?? '2');
    $mode = (string) ($options['mode'] ?? 'vuln');

    if ($mode === 'safe') {
        $sql = "SELECT id, owner_user_id, item_name, total_amount, status FROM orders WHERE id = $orderId AND owner_user_id = $actorUserId";
    } else {
        $sql = "SELECT id, owner_user_id, item_name, total_amount, status FROM orders WHERE id = $orderId";
    }
    $res = $db->query($sql);

    if ($res === false) {
        json_response(array(
            'ok' => false,
            'category' => 'idor',
            'sink' => 'mysqli::query',
            'actor_user_id' => $actorUserId,
            'sql' => $sql,
            'db_error' => $db->error,
        ));
        return;
    }

    $rows = array();
    if ($res instanceof mysqli_result) {
        while ($row = $res->fetch_assoc()) {
            $rows[] = $row;
        }
    }

    json_response(array(
        'ok' => true,
        'category' => 'idor',
        'sink' => 'object lookup without owner enforcement',
        'actor_user_id' => $actorUserId,
        'mode' => $mode,
        'sql' => $sql,
        'rows' => $rows,
    ));
}

function route_api_json_state_change_email(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }

    $db = db_connect();
    if ($db === null) {
        json_response(array('ok' => false, 'error' => 'database_unavailable'), 503);
        return;
    }

    seed_database($db);
    $user = is_array($payload['user'] ?? null) ? $payload['user'] : array();
    $profile = is_array($payload['profile'] ?? null) ? $payload['profile'] : array();
    $userId = (string) ($user['id'] ?? '1');
    $email = (string) ($profile['email'] ?? 'alice+auto-json@example.test');
    $sql = "UPDATE users SET email='" . $db->real_escape_string($email) . "' WHERE id=$userId";
    $ok = $db->query($sql);

    json_response(array(
        'ok' => $ok !== false,
        'category' => 'state_change',
        'sink' => 'mysqli::query UPDATE without CSRF/auth enforcement',
        'user_id' => $userId,
        'email' => $email,
        'sql' => $sql,
        'affected_rows' => $db->affected_rows,
        'db_error' => $ok === false ? $db->error : null,
    ));
}

function route_api_json_session_set_cookie(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }

    $cookie = is_array($payload['cookie'] ?? null) ? $payload['cookie'] : array();
    $options = is_array($payload['options'] ?? null) ? $payload['options'] : array();
    $name = (string) ($cookie['name'] ?? 'auto_json_token');
    $value = (string) ($cookie['value'] ?? 'demo-auto-json');
    $maxAge = (int) ($options['max_age'] ?? 3600);
    if ($maxAge <= 0 || $maxAge > 86400) {
        $maxAge = 3600;
    }
    $safeName = preg_replace('/[^A-Za-z0-9_.-]/', '_', $name);
    $safeName = is_string($safeName) && $safeName !== '' ? $safeName : 'auto_json_token';

    setcookie($safeName, $value, array(
        'expires' => time() + $maxAge,
        'path' => '/',
        'secure' => false,
        'httponly' => false,
        'samesite' => 'Lax',
    ));
    $_COOKIE[$safeName] = $value;

    json_response(array(
        'ok' => true,
        'category' => 'session',
        'sink' => 'setcookie',
        'requested_cookie_name' => $name,
        'cookie_name' => $safeName,
        'cookie_value' => $value,
        'flags' => array('secure' => false, 'httponly' => false, 'samesite' => 'Lax', 'max_age' => $maxAge),
    ));
}

/**
 * @param array<string, mixed> $defaultPayload
 */
function render_auto_json_trigger(string $title, string $routePath, string $targetCategory, string $apiPath, string $jsonPath, string $sink, array $defaultPayload): void
{
    $defaultJson = json_encode($defaultPayload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    if (!is_string($defaultJson)) {
        $defaultJson = '{}';
    }

    page_start($title);
    render_exploit_guide($routePath);
    echo '<div class="panel">';
    echo '<h2>Auto-Activated JSON Request</h2>';
    echo '<p>This crawlable page sends the JSON request once on page load, then shows the response inline for browser-driven scanners.</p>';
    echo '<p><strong>Trigger Event:</strong> <code>DOMContentLoaded</code></p>';
    echo '<p><strong>Target Category:</strong> <code>' . esc($targetCategory) . '</code></p>';
    echo '<p><strong>Method:</strong> <code>POST</code></p>';
    echo '<p><strong>API Endpoint:</strong> <code>' . esc($apiPath) . '</code></p>';
    echo '<p><strong>Vulnerable JSON Path:</strong> <code>' . esc($jsonPath) . '</code></p>';
    echo '<p><strong>Sink:</strong> <code>' . esc($sink) . '</code></p>';
    echo '<form id="auto-json-form">';
    echo '<label for="auto-json-payload">JSON Payload</label><br>';
    echo '<textarea id="auto-json-payload" rows="14" cols="100" spellcheck="false">' . esc($defaultJson) . '</textarea><br>';
    echo '<button type="submit">Run Again</button> ';
    echo '<button type="button" id="auto-json-reset">Reset Payload</button>';
    echo '</form>';
    echo '<p><strong>Last Trigger:</strong> <span id="auto-json-event" class="pill">not fired</span></p>';
    echo '<p><strong>Response:</strong> <span id="auto-json-status" class="pill">not sent</span></p>';
    echo '<pre id="auto-json-response"></pre>';
    echo '</div>';

    $jsApiPath = json_encode($apiPath, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
    $jsDefaultJson = json_encode($defaultJson, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
    echo '<script>';
    echo '(() => {';
    echo 'const apiPath = ' . $jsApiPath . ';';
    echo 'const defaultPayload = ' . $jsDefaultJson . ';';
    echo 'const form = document.getElementById("auto-json-form");';
    echo 'const textarea = document.getElementById("auto-json-payload");';
    echo 'const reset = document.getElementById("auto-json-reset");';
    echo 'const eventLabel = document.getElementById("auto-json-event");';
    echo 'const status = document.getElementById("auto-json-status");';
    echo 'const output = document.getElementById("auto-json-response");';
    echo 'textarea.value = defaultPayload;';
    echo 'async function sendPayload(triggerEvent) {';
    echo 'eventLabel.textContent = triggerEvent;';
    echo 'status.textContent = "sending";';
    echo 'output.textContent = "";';
    echo 'try {';
    echo 'const response = await fetch(apiPath, {method: "POST", headers: {"Content-Type": "application/json"}, credentials: "same-origin", body: textarea.value});';
    echo 'const text = await response.text();';
    echo 'status.textContent = response.status + " " + response.statusText;';
    echo 'try { output.textContent = JSON.stringify(JSON.parse(text), null, 2); } catch (_err) { output.textContent = text; }';
    echo '} catch (err) { status.textContent = "request failed"; output.textContent = String(err); }';
    echo '}';
    echo 'reset.addEventListener("click", () => { textarea.value = defaultPayload; eventLabel.textContent = "not fired"; status.textContent = "not sent"; output.textContent = ""; });';
    echo 'form.addEventListener("submit", (event) => { event.preventDefault(); void sendPayload("manual_run_again"); });';
    echo 'document.addEventListener("DOMContentLoaded", () => { void sendPayload("page_load"); });';
    echo '})();';
    echo '</script>';
    page_end();
}

/**
 * @param array<string, mixed> $defaultPayload
 */
function render_json_playground(string $title, string $apiPath, string $jsonPath, string $sink, array $defaultPayload): void
{
    $defaultJson = json_encode($defaultPayload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    if (!is_string($defaultJson)) {
        $defaultJson = '{}';
    }

    page_start($title);
    render_exploit_guide($apiPath);
    echo '<div class="panel">';
    echo '<h2>Interactive JSON Request</h2>';
    echo '<p><strong>Method:</strong> <code>POST</code></p>';
    echo '<p><strong>API Endpoint:</strong> <code>' . esc($apiPath) . '</code></p>';
    echo '<p><strong>Vulnerable JSON Path:</strong> <code>' . esc($jsonPath) . '</code></p>';
    echo '<p><strong>Sink:</strong> <code>' . esc($sink) . '</code></p>';
    echo '<form id="json-playground-form">';
    echo '<label for="json-payload">JSON Payload</label><br>';
    echo '<textarea id="json-payload" rows="14" cols="100" spellcheck="false">' . esc($defaultJson) . '</textarea><br>';
    echo '<button type="submit">Send JSON</button> ';
    echo '<button type="button" id="json-reset">Reset</button>';
    echo '</form>';
    echo '<p><strong>Response:</strong> <span id="json-status" class="pill">not sent</span></p>';
    echo '<pre id="json-response"></pre>';
    echo '</div>';

    $jsApiPath = json_encode($apiPath, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
    $jsDefaultJson = json_encode($defaultJson, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
    echo '<script>';
    echo '(() => {';
    echo 'const apiPath = ' . $jsApiPath . ';';
    echo 'const defaultPayload = ' . $jsDefaultJson . ';';
    echo 'const form = document.getElementById("json-playground-form");';
    echo 'const textarea = document.getElementById("json-payload");';
    echo 'const reset = document.getElementById("json-reset");';
    echo 'const status = document.getElementById("json-status");';
    echo 'const output = document.getElementById("json-response");';
    echo 'reset.addEventListener("click", () => { textarea.value = defaultPayload; status.textContent = "not sent"; output.textContent = ""; });';
    echo 'form.addEventListener("submit", async (event) => {';
    echo 'event.preventDefault();';
    echo 'status.textContent = "sending";';
    echo 'output.textContent = "";';
    echo 'try {';
    echo 'const response = await fetch(apiPath, {method: "POST", headers: {"Content-Type": "application/json"}, credentials: "same-origin", body: textarea.value});';
    echo 'const text = await response.text();';
    echo 'status.textContent = response.status + " " + response.statusText;';
    echo 'try { output.textContent = JSON.stringify(JSON.parse(text), null, 2); } catch (_err) { output.textContent = text; }';
    echo '} catch (err) { status.textContent = "request failed"; output.textContent = String(err); }';
    echo '});';
    echo '})();';
    echo '</script>';
    page_end();
}

function route_auto_rce_header_command(string $method): void
{
    render_auto_json_trigger('Auto JSON RCE - Header Command', '/auto/rce/header-command', 'rce', '/api/json/rce/header-command', 'request.headers.X-Command', 'system($headers["X-Command"])', array(
        'request' => array('headers' => array('X-Command' => 'printf auto_rce_header_ok'), 'mode' => 'healthcheck'),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'header_map', 'trigger' => 'page_load'),
    ));
}

function route_auto_rce_task_matrix(string $method): void
{
    render_auto_json_trigger('Auto JSON RCE - Task Matrix', '/auto/rce/task-matrix', 'rce', '/api/json/rce/task-matrix', 'matrix.rows[1].cells.command', 'shell_exec(matrix command cell)', array(
        'matrix' => array('rows' => array(
            array('name' => 'noop', 'cells' => array('command' => 'printf ignored')),
            array('name' => 'run', 'cells' => array('command' => 'printf auto_rce_matrix_ok')),
        )),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'matrix_cells', 'trigger' => 'page_load'),
    ));
}

function route_auto_sqli_join_fragment(string $method): void
{
    render_auto_json_trigger('Auto JSON SQLi - Join Fragment', '/auto/sqli/join-fragment', 'sqli', '/api/json/sqli/join-fragment', 'query.join.on_extra', 'mysqli::query JOIN fragment', array(
        'query' => array('join' => array('on_extra' => 'OR 1=1')),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'join_fragment', 'trigger' => 'page_load'),
    ));
}

function route_auto_sqli_having_metric(string $method): void
{
    render_auto_json_trigger('Auto JSON SQLi - Having Metric', '/auto/sqli/having-metric', 'sqli', '/api/json/sqli/having-metric', 'analytics.metrics[0].having', 'mysqli::query HAVING fragment', array(
        'analytics' => array('metrics' => array(array('name' => 'order_count', 'having' => 'COUNT(*) >= 0 OR 1=1'))),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'analytics_having', 'trigger' => 'page_load'),
    ));
}

function route_auto_sqli_limit_offset(string $method): void
{
    render_auto_json_trigger('Auto JSON SQLi - Limit Offset', '/auto/sqli/limit-offset', 'sqli', '/api/json/sqli/limit-offset', 'page.limit + page.offset', 'mysqli::query pagination fragment', array(
        'page' => array('limit' => '10', 'offset' => '0 OR 1=1'),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'pagination_object', 'trigger' => 'page_load'),
    ));
}

function route_auto_sqli_json_search_doc(string $method): void
{
    render_auto_json_trigger('Auto JSON SQLi - Search Document', '/auto/sqli/json-search-doc', 'sqli', '/api/json/sqli/json-search-doc', 'document.sections[0].filters.term', 'mysqli::query LIKE clause', array(
        'document' => array('sections' => array(array('name' => 'users', 'filters' => array('term' => "%' OR '1'='1")))),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'document_filter', 'trigger' => 'page_load'),
    ));
}

function route_auto_file_archive_extract(string $method): void
{
    render_auto_json_trigger('Auto JSON File - Archive Extract', '/auto/file/archive-extract', 'file_write', '/api/json/file/archive-extract', 'archive.entries[0].path', 'file_put_contents archive path', array(
        'archive' => array('entries' => array(array('path' => 'auto_archive/../auto_archive_pwn.txt', 'content' => 'auto_archive_extract_ok'))),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'archive_entries', 'trigger' => 'page_load'),
    ));
}

function route_auto_file_log_read(string $method): void
{
    render_auto_json_trigger('Auto JSON File - Log Read', '/auto/file/log-read', 'lfi', '/api/json/file/log-read', 'log.segments[]', 'file_get_contents log path', array(
        'log' => array('segments' => array('pages', 'home.php')),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'path_segments', 'trigger' => 'page_load'),
    ));
}

function route_auto_file_export_name(string $method): void
{
    render_auto_json_trigger('Auto JSON File - Export Name', '/auto/file/export-name', 'file_write', '/api/json/file/export-name', 'export.filename', 'file_put_contents export filename', array(
        'export' => array('filename' => 'auto_export_name.json', 'body' => '{"auto_export_name":"ok"}'),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'export_descriptor', 'trigger' => 'page_load'),
    ));
}

function route_auto_ssrf_rss_feed(string $method): void
{
    render_auto_json_trigger('Auto JSON SSRF - RSS Feed', '/auto/ssrf/rss-feed', 'ssrf', '/api/json/ssrf/rss-feed', 'feeds[0].url', 'file_get_contents feed URL', array(
        'feeds' => array(array('name' => 'lab', 'url' => 'data://text/plain,auto_ssrf_rss_ok')),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'feed_array', 'trigger' => 'page_load'),
    ));
}

function route_auto_ssrf_proxy_chain(string $method): void
{
    render_auto_json_trigger('Auto JSON SSRF - Proxy Chain', '/auto/ssrf/proxy-chain', 'ssrf', '/api/json/ssrf/proxy-chain', 'proxy.chain[1].target.href', 'file_get_contents proxy target', array(
        'proxy' => array('chain' => array(
            array('type' => 'cache', 'target' => array('href' => 'data://text/plain,ignored')),
            array('type' => 'origin', 'target' => array('href' => 'data://text/plain,auto_ssrf_proxy_chain_ok')),
        )),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'proxy_chain', 'trigger' => 'page_load'),
    ));
}

function route_auto_ssrf_cloud_metadata(string $method): void
{
    render_auto_json_trigger('Auto JSON SSRF - Cloud Metadata', '/auto/ssrf/cloud-metadata', 'ssrf', '/api/json/ssrf/cloud-metadata', 'cloud.metadata.url', 'file_get_contents metadata URL', array(
        'cloud' => array('provider' => 'lab', 'metadata' => array('url' => 'data://text/plain,auto_ssrf_metadata_ok')),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'cloud_metadata', 'trigger' => 'page_load'),
    ));
}

function route_auto_xss_notification_template(string $method): void
{
    render_auto_json_trigger('Auto JSON XSS - Notification Template', '/auto/xss/notification-template', 'xss', '/api/json/xss/notification-template', 'notification.template', 'HTML notification interpolation', array(
        'notification' => array('template' => '<strong>Notice</strong><img src=x onerror=alert(1)>', 'vars' => array('name' => 'alice')),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'template_vars', 'trigger' => 'page_load'),
    ));
}

function route_auto_xss_table_cell(string $method): void
{
    render_auto_json_trigger('Auto JSON XSS - Table Cell', '/auto/xss/table-cell', 'xss', '/api/json/xss/table-cell', 'table.rows[0].cells[1].value', 'unsafe table cell HTML', array(
        'table' => array('rows' => array(array('cells' => array(array('value' => 'user'), array('value' => '<svg onload=alert(1)>'))))),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'table_cells', 'trigger' => 'page_load'),
    ));
}

function route_auto_xss_email_preview(string $method): void
{
    render_auto_json_trigger('Auto JSON XSS - Email Preview', '/auto/xss/email-preview', 'xss', '/api/json/xss/email-preview', 'email.parts.html', 'email preview HTML', array(
        'email' => array('subject' => 'Auto preview', 'parts' => array('html' => '<a href=javascript:alert(1)>auto_email_xss</a>')),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'email_parts', 'trigger' => 'page_load'),
    ));
}

function route_auto_idor_project_role(string $method): void
{
    render_auto_json_trigger('Auto JSON IDOR - Project Role', '/auto/idor/project-role', 'idor', '/api/json/idor/project-role', 'project.members[0].user_id', 'project role lookup without membership enforcement', array(
        'actor' => array('user_id' => '1'),
        'project' => array('id' => 'lab-project', 'members' => array(array('user_id' => '3'))),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'project_members', 'trigger' => 'page_load'),
    ));
}

function route_auto_idor_api_key_read(string $method): void
{
    render_auto_json_trigger('Auto JSON IDOR - API Key Read', '/auto/idor/api-key-read', 'idor', '/api/json/idor/api-key-read', 'secrets.owner.user_id', 'API key derivation without owner enforcement', array(
        'actor' => array('user_id' => '1'),
        'secrets' => array('owner' => array('user_id' => '3'), 'scope' => 'admin-api'),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'secret_owner', 'trigger' => 'page_load'),
    ));
}

function route_auto_auth_oauth_callback(string $method): void
{
    render_auto_json_trigger('Auto JSON Auth - OAuth Callback', '/auto/auth/oauth-callback', 'auth', '/api/json/auth/oauth-callback', 'oauth.claims.sub', 'OAuth callback trusts JSON claims', array(
        'oauth' => array('provider' => 'lab-idp', 'claims' => array('sub' => '3', 'email' => 'admin@example.test')),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'oauth_claims', 'trigger' => 'page_load'),
    ));
}

function route_auto_auth_jwt_none(string $method): void
{
    render_auto_json_trigger('Auto JSON Auth - JWT None', '/auto/auth/jwt-none', 'auth', '/api/json/auth/jwt-none', 'jwt.claims.user_id', 'unsigned JWT claims trusted', array(
        'jwt' => array('header' => array('alg' => 'none', 'typ' => 'JWT'), 'claims' => array('user_id' => '3', 'role' => 'admin')),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'jwt_parts', 'trigger' => 'page_load'),
    ));
}

function route_auto_state_preferences_merge(string $method): void
{
    render_auto_json_trigger('Auto JSON State - Preferences Merge', '/auto/state/preferences-merge', 'state_change', '/api/json/state/preferences-merge', 'preferences.overrides.is_admin', 'session preference merge', array(
        'user' => array('id' => '1'),
        'preferences' => array('theme' => 'dark', 'overrides' => array('is_admin' => true, 'debug_panel' => true)),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'deep_merge', 'trigger' => 'page_load'),
    ));
}

function route_auto_state_inventory_adjust(string $method): void
{
    render_auto_json_trigger('Auto JSON State - Inventory Adjust', '/auto/state/inventory-adjust', 'state_change', '/api/json/state/inventory-adjust', 'adjustments[0].delta', 'inventory adjustment from JSON', array(
        'adjustments' => array(array('sku' => 'LAB-001', 'delta' => '-999', 'reason' => 'auto-fuzzer-test')),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'adjustment_array', 'trigger' => 'page_load'),
    ));
}

function route_auto_deserialization_signed_envelope(string $method): void
{
    render_auto_json_trigger('Auto JSON Deserialization - Signed Envelope', '/auto/deserialization/signed-envelope', 'deserialization', '/api/json/deserialization/signed-envelope', 'envelope.payload.serialized_b64', 'signature ignored before unserialize', array(
        'envelope' => array('signature' => 'not-validated', 'payload' => array('serialized_b64' => base64_encode('O:8:"stdClass":1:{s:7:"message";s:22:"auto_deser_envelope_ok";}'))),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'signed_envelope', 'trigger' => 'page_load'),
    ));
}

function route_auto_redirect_deep_link(string $method): void
{
    render_auto_json_trigger('Auto JSON Redirect - Deep Link', '/auto/redirect/deep-link', 'open_redirect', '/api/json/redirect/deep-link', 'app.links[0].href', 'Location header from deep link JSON', array(
        'app' => array('links' => array(array('rel' => 'continue', 'href' => 'https://example.org/auto-deep-link'))),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'link_array', 'trigger' => 'page_load'),
    ));
}

function route_auto_cors_tenant_origin_list(string $method): void
{
    render_auto_json_trigger('Auto JSON CORS - Tenant Origin List', '/auto/cors/tenant-origin-list', 'cors', '/api/json/cors/tenant-origin-list', 'tenants[0].allowed_origins[1]', 'CORS tenant allowlist reflection', array(
        'tenants' => array(array('id' => 'lab', 'allowed_origins' => array('https://app.example.test', 'https://evil-tenant.example.test'))),
        'metadata' => array('source' => 'auto-json-lab', 'shape' => 'tenant_origin_array', 'trigger' => 'page_load'),
    ));
}

function route_api_json_rce_header_command(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $request = is_array($payload['request'] ?? null) ? $payload['request'] : array();
    $headers = is_array($request['headers'] ?? null) ? $request['headers'] : array();
    $cmd = (string) ($headers['X-Command'] ?? 'printf auto_rce_header_ok');
    ob_start();
    @system($cmd);
    $output = (string) ob_get_clean();
    json_response(array('ok' => true, 'category' => 'rce', 'sink' => 'system header command', 'vulnerable_json_path' => 'request.headers.X-Command', 'command' => $cmd, 'output_preview' => substr($output, 0, 4000)));
}

function route_api_json_rce_task_matrix(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $matrix = is_array($payload['matrix'] ?? null) ? $payload['matrix'] : array();
    $rows = is_array($matrix['rows'] ?? null) ? $matrix['rows'] : array();
    $row = is_array($rows[1] ?? null) ? $rows[1] : array();
    $cells = is_array($row['cells'] ?? null) ? $row['cells'] : array();
    $cmd = (string) ($cells['command'] ?? 'printf auto_rce_matrix_ok');
    $output = @shell_exec($cmd);
    json_response(array('ok' => true, 'category' => 'rce', 'sink' => 'shell_exec matrix cell', 'vulnerable_json_path' => 'matrix.rows[1].cells.command', 'command' => $cmd, 'output_preview' => substr((string) $output, 0, 4000)));
}

function route_api_json_sqli_join_fragment(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $db = db_connect();
    if ($db === null) {
        json_response(array('ok' => false, 'error' => 'database_unavailable'), 503);
        return;
    }
    seed_database($db);
    $query = is_array($payload['query'] ?? null) ? $payload['query'] : array();
    $join = is_array($query['join'] ?? null) ? $query['join'] : array();
    $extra = (string) ($join['on_extra'] ?? 'OR 1=1');
    json_query_response($db, 'sqli', 'mysqli::query JOIN fragment', 'query.join.on_extra', "SELECT u.id, u.username, a.balance FROM users u JOIN accounts a ON a.user_id = u.id $extra");
}

function route_api_json_sqli_having_metric(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $db = db_connect();
    if ($db === null) {
        json_response(array('ok' => false, 'error' => 'database_unavailable'), 503);
        return;
    }
    seed_database($db);
    $analytics = is_array($payload['analytics'] ?? null) ? $payload['analytics'] : array();
    $metrics = is_array($analytics['metrics'] ?? null) ? $analytics['metrics'] : array();
    $metric = is_array($metrics[0] ?? null) ? $metrics[0] : array();
    $having = (string) ($metric['having'] ?? 'COUNT(*) >= 0 OR 1=1');
    json_query_response($db, 'sqli', 'mysqli::query HAVING fragment', 'analytics.metrics[0].having', "SELECT owner_user_id, COUNT(*) AS c FROM orders GROUP BY owner_user_id HAVING $having");
}

function route_api_json_sqli_limit_offset(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $db = db_connect();
    if ($db === null) {
        json_response(array('ok' => false, 'error' => 'database_unavailable'), 503);
        return;
    }
    seed_database($db);
    $page = is_array($payload['page'] ?? null) ? $payload['page'] : array();
    $limit = (string) ($page['limit'] ?? '10');
    $offset = (string) ($page['offset'] ?? '0 OR 1=1');
    json_query_response($db, 'sqli', 'mysqli::query pagination fragment', 'page.limit + page.offset', "SELECT id, username, email FROM users ORDER BY id LIMIT $limit OFFSET $offset");
}

function route_api_json_sqli_json_search_doc(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $db = db_connect();
    if ($db === null) {
        json_response(array('ok' => false, 'error' => 'database_unavailable'), 503);
        return;
    }
    seed_database($db);
    $document = is_array($payload['document'] ?? null) ? $payload['document'] : array();
    $sections = is_array($document['sections'] ?? null) ? $document['sections'] : array();
    $section = is_array($sections[0] ?? null) ? $sections[0] : array();
    $filters = is_array($section['filters'] ?? null) ? $section['filters'] : array();
    $term = (string) ($filters['term'] ?? "%' OR '1'='1");
    json_query_response($db, 'sqli', 'mysqli::query LIKE clause', 'document.sections[0].filters.term', "SELECT id, username, email FROM users WHERE username LIKE '$term'");
}

function route_api_json_file_archive_extract(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $archive = is_array($payload['archive'] ?? null) ? $payload['archive'] : array();
    $entries = is_array($archive['entries'] ?? null) ? $archive['entries'] : array();
    $entry = is_array($entries[0] ?? null) ? $entries[0] : array();
    $path = (string) ($entry['path'] ?? 'auto_archive/../auto_archive_pwn.txt');
    $content = (string) ($entry['content'] ?? 'auto_archive_extract_ok');
    $cfg = app_config();
    $target = $cfg['upload_dir'] . '/' . $path;
    $dir = dirname($target);
    if (!is_dir($dir)) {
        @mkdir($dir, 0777, true);
    }
    $bytes = @file_put_contents($target, $content);
    json_response(array('ok' => $bytes !== false, 'category' => 'file_write', 'sink' => 'file_put_contents archive path', 'vulnerable_json_path' => 'archive.entries[0].path', 'target' => $target, 'bytes_written' => $bytes === false ? 0 : $bytes, 'content_preview' => substr($content, 0, 4000)));
}

function route_api_json_file_log_read(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $log = is_array($payload['log'] ?? null) ? $payload['log'] : array();
    $segments = is_array($log['segments'] ?? null) ? $log['segments'] : array('pages', 'home.php');
    $parts = array();
    foreach ($segments as $segment) {
        if (is_scalar($segment)) {
            $parts[] = (string) $segment;
        }
    }
    $target = __DIR__ . '/' . implode('/', $parts);
    $body = @file_get_contents($target);
    json_response(array('ok' => is_string($body), 'category' => 'lfi', 'sink' => 'file_get_contents log path', 'vulnerable_json_path' => 'log.segments[]', 'target' => $target, 'read_preview' => is_string($body) ? substr($body, 0, 4000) : null, 'read_failed' => !is_string($body)));
}

function route_api_json_file_export_name(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $export = is_array($payload['export'] ?? null) ? $payload['export'] : array();
    $filename = (string) ($export['filename'] ?? 'auto_export_name.json');
    $body = (string) ($export['body'] ?? '{"auto_export_name":"ok"}');
    $cfg = app_config();
    if (!is_dir($cfg['upload_dir'])) {
        @mkdir($cfg['upload_dir'], 0777, true);
    }
    $target = $cfg['upload_dir'] . '/' . $filename;
    $bytes = @file_put_contents($target, $body);
    json_response(array('ok' => $bytes !== false, 'category' => 'file_write', 'sink' => 'file_put_contents export filename', 'vulnerable_json_path' => 'export.filename', 'target' => $target, 'bytes_written' => $bytes === false ? 0 : $bytes, 'body_preview' => substr($body, 0, 4000)));
}

function route_api_json_ssrf_rss_feed(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $feeds = is_array($payload['feeds'] ?? null) ? $payload['feeds'] : array();
    $feed = is_array($feeds[0] ?? null) ? $feeds[0] : array();
    json_fetch_response((string) ($feed['url'] ?? 'data://text/plain,auto_ssrf_rss_ok'), 'feeds[0].url');
}

function route_api_json_ssrf_proxy_chain(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $proxy = is_array($payload['proxy'] ?? null) ? $payload['proxy'] : array();
    $chain = is_array($proxy['chain'] ?? null) ? $proxy['chain'] : array();
    $hop = is_array($chain[1] ?? null) ? $chain[1] : array();
    $target = is_array($hop['target'] ?? null) ? $hop['target'] : array();
    json_fetch_response((string) ($target['href'] ?? 'data://text/plain,auto_ssrf_proxy_chain_ok'), 'proxy.chain[1].target.href');
}

function route_api_json_ssrf_cloud_metadata(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $cloud = is_array($payload['cloud'] ?? null) ? $payload['cloud'] : array();
    $metadata = is_array($cloud['metadata'] ?? null) ? $cloud['metadata'] : array();
    json_fetch_response((string) ($metadata['url'] ?? 'data://text/plain,auto_ssrf_metadata_ok'), 'cloud.metadata.url');
}

function route_api_json_xss_notification_template(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $notification = is_array($payload['notification'] ?? null) ? $payload['notification'] : array();
    $template = (string) ($notification['template'] ?? '<strong>Notice</strong><img src=x onerror=alert(1)>');
    $html = '<div class="notification">' . $template . '</div>';
    json_response(array('ok' => true, 'category' => 'xss', 'sink' => 'HTML notification interpolation', 'vulnerable_json_path' => 'notification.template', 'html_preview' => substr($html, 0, 4000)));
}

function route_api_json_xss_table_cell(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $table = is_array($payload['table'] ?? null) ? $payload['table'] : array();
    $rows = is_array($table['rows'] ?? null) ? $table['rows'] : array();
    $row = is_array($rows[0] ?? null) ? $rows[0] : array();
    $cells = is_array($row['cells'] ?? null) ? $row['cells'] : array();
    $cell = is_array($cells[1] ?? null) ? $cells[1] : array();
    $value = (string) ($cell['value'] ?? '<svg onload=alert(1)>');
    $html = '<table><tr><td>user</td><td>' . $value . '</td></tr></table>';
    json_response(array('ok' => true, 'category' => 'xss', 'sink' => 'unsafe table cell HTML', 'vulnerable_json_path' => 'table.rows[0].cells[1].value', 'html_preview' => substr($html, 0, 4000)));
}

function route_api_json_xss_email_preview(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $email = is_array($payload['email'] ?? null) ? $payload['email'] : array();
    $parts = is_array($email['parts'] ?? null) ? $email['parts'] : array();
    $htmlPart = (string) ($parts['html'] ?? '<a href=javascript:alert(1)>auto_email_xss</a>');
    $html = '<section class="email-preview"><h2>' . (string) ($email['subject'] ?? 'Auto preview') . '</h2>' . $htmlPart . '</section>';
    json_response(array('ok' => true, 'category' => 'xss', 'sink' => 'email preview HTML', 'vulnerable_json_path' => 'email.parts.html', 'html_preview' => substr($html, 0, 4000)));
}

function route_api_json_idor_project_role(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $db = db_connect();
    if ($db === null) {
        json_response(array('ok' => false, 'error' => 'database_unavailable'), 503);
        return;
    }
    seed_database($db);
    $project = is_array($payload['project'] ?? null) ? $payload['project'] : array();
    $members = is_array($project['members'] ?? null) ? $project['members'] : array();
    $member = is_array($members[0] ?? null) ? $members[0] : array();
    $userId = (string) ($member['user_id'] ?? '3');
    json_query_response($db, 'idor', 'project role lookup without membership enforcement', 'project.members[0].user_id', "SELECT id, username, email, role FROM users WHERE id = $userId");
}

function route_api_json_idor_api_key_read(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $secrets = is_array($payload['secrets'] ?? null) ? $payload['secrets'] : array();
    $owner = is_array($secrets['owner'] ?? null) ? $secrets['owner'] : array();
    $ownerId = (string) ($owner['user_id'] ?? '3');
    $scope = (string) ($secrets['scope'] ?? 'admin-api');
    $apiKey = 'lab_' . substr(hash('sha256', $ownerId . ':' . $scope . ':auto'), 0, 24);
    json_response(array('ok' => true, 'category' => 'idor', 'sink' => 'API key derivation without owner enforcement', 'vulnerable_json_path' => 'secrets.owner.user_id', 'owner_user_id' => $ownerId, 'scope' => $scope, 'api_key_preview' => $apiKey));
}

function route_api_json_auth_oauth_callback(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $db = db_connect();
    if ($db === null) {
        json_response(array('ok' => false, 'error' => 'database_unavailable'), 503);
        return;
    }
    seed_database($db);
    $oauth = is_array($payload['oauth'] ?? null) ? $payload['oauth'] : array();
    $claims = is_array($oauth['claims'] ?? null) ? $oauth['claims'] : array();
    $sub = (string) ($claims['sub'] ?? '3');
    $res = $db->query("SELECT id, username, role, email FROM users WHERE id=$sub");
    $row = $res instanceof mysqli_result ? $res->fetch_assoc() : null;
    if (is_array($row)) {
        $_SESSION['user'] = array('id' => (int) $row['id'], 'username' => (string) $row['username'], 'role' => (string) $row['role'], 'email' => (string) $row['email']);
    }
    json_response(array('ok' => is_array($row), 'category' => 'auth', 'sink' => 'OAuth callback trusts JSON claims', 'vulnerable_json_path' => 'oauth.claims.sub', 'claims' => $claims, 'session_user' => $_SESSION['user'] ?? null));
}

function route_api_json_auth_jwt_none(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $jwt = is_array($payload['jwt'] ?? null) ? $payload['jwt'] : array();
    $header = is_array($jwt['header'] ?? null) ? $jwt['header'] : array('alg' => 'none');
    $claims = is_array($jwt['claims'] ?? null) ? $jwt['claims'] : array('user_id' => '3', 'role' => 'admin');
    $_SESSION['jwt_user'] = $claims;
    json_response(array('ok' => true, 'category' => 'auth', 'sink' => 'unsigned JWT claims trusted', 'vulnerable_json_path' => 'jwt.claims.user_id', 'header' => $header, 'claims' => $claims, 'session_jwt_user' => $_SESSION['jwt_user']));
}

function route_api_json_state_preferences_merge(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $preferences = is_array($payload['preferences'] ?? null) ? $payload['preferences'] : array();
    $_SESSION['preferences'] = array_replace_recursive(is_array($_SESSION['preferences'] ?? null) ? $_SESSION['preferences'] : array('theme' => 'light'), $preferences);
    json_response(array('ok' => true, 'category' => 'state_change', 'sink' => 'session preference merge', 'vulnerable_json_path' => 'preferences.overrides.is_admin', 'merged_preferences' => $_SESSION['preferences']));
}

function route_api_json_state_inventory_adjust(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $adjustments = is_array($payload['adjustments'] ?? null) ? $payload['adjustments'] : array();
    $adjustment = is_array($adjustments[0] ?? null) ? $adjustments[0] : array();
    $sku = (string) ($adjustment['sku'] ?? 'LAB-001');
    $delta = (string) ($adjustment['delta'] ?? '-999');
    $cfg = app_config();
    if (!is_dir($cfg['upload_dir'])) {
        @mkdir($cfg['upload_dir'], 0777, true);
    }
    $target = $cfg['upload_dir'] . '/auto_inventory_adjust.json';
    $bytes = @file_put_contents($target, json_encode(array('sku' => $sku, 'delta' => $delta, 'payload' => $payload), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    json_response(array('ok' => $bytes !== false, 'category' => 'state_change', 'sink' => 'inventory adjustment from JSON', 'vulnerable_json_path' => 'adjustments[0].delta', 'sku' => $sku, 'trusted_delta' => $delta, 'target' => $target, 'bytes_written' => $bytes === false ? 0 : $bytes));
}

function route_api_json_deserialization_signed_envelope(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $envelope = is_array($payload['envelope'] ?? null) ? $payload['envelope'] : array();
    $inner = is_array($envelope['payload'] ?? null) ? $envelope['payload'] : array();
    $b64 = (string) ($inner['serialized_b64'] ?? base64_encode('O:8:"stdClass":1:{s:7:"message";s:22:"auto_deser_envelope_ok";}'));
    $serialized = base64_decode($b64, true);
    $serialized = is_string($serialized) ? $serialized : '';
    $value = @unserialize($serialized);
    json_response(array('ok' => $value !== false || $serialized === 'b:0;', 'category' => 'deserialization', 'sink' => 'signature ignored before unserialize', 'vulnerable_json_path' => 'envelope.payload.serialized_b64', 'signature' => (string) ($envelope['signature'] ?? ''), 'serialized_preview' => substr($serialized, 0, 4000), 'result_type' => is_object($value) ? get_class($value) : gettype($value), 'result_preview' => substr(print_r($value, true), 0, 4000)));
}

function route_api_json_redirect_deep_link(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $app = is_array($payload['app'] ?? null) ? $payload['app'] : array();
    $links = is_array($app['links'] ?? null) ? $app['links'] : array();
    $link = is_array($links[0] ?? null) ? $links[0] : array();
    $href = (string) ($link['href'] ?? 'https://example.org/auto-deep-link');
    json_response(array('ok' => true, 'category' => 'open_redirect', 'sink' => 'Location header from deep link JSON', 'vulnerable_json_path' => 'app.links[0].href', 'redirect_target' => $href), 302, array('Location' => $href));
}

function route_api_json_cors_tenant_origin_list(string $method): void
{
    $payload = read_json_post_body($method);
    if ($payload === null) {
        return;
    }
    $tenants = is_array($payload['tenants'] ?? null) ? $payload['tenants'] : array();
    $tenant = is_array($tenants[0] ?? null) ? $tenants[0] : array();
    $origins = is_array($tenant['allowed_origins'] ?? null) ? $tenant['allowed_origins'] : array('https://app.example.test', 'https://evil-tenant.example.test');
    $origin = is_scalar($origins[1] ?? null) ? (string) $origins[1] : 'https://evil-tenant.example.test';
    json_response(array('ok' => true, 'category' => 'cors', 'sink' => 'CORS tenant allowlist reflection', 'vulnerable_json_path' => 'tenants[0].allowed_origins[1]', 'reflected_origin' => $origin), 200, array(
        'Access-Control-Allow-Origin' => $origin,
        'Access-Control-Allow-Credentials' => 'true',
    ));
}

function read_json_post_body(string $method): ?array
{
    if ($method !== 'POST') {
        json_response(array(
            'ok' => false,
            'error' => 'method_not_allowed',
            'expected_method' => 'POST',
        ), 405, array('Allow' => 'POST'));
        return null;
    }

    $contentType = strtolower((string) ($_SERVER['CONTENT_TYPE'] ?? $_SERVER['HTTP_CONTENT_TYPE'] ?? ''));
    if (!str_contains($contentType, 'application/json')) {
        json_response(array(
            'ok' => false,
            'error' => 'unsupported_media_type',
            'expected_content_type' => 'application/json',
        ), 415);
        return null;
    }

    $raw = file_get_contents('php://input');
    if (!is_string($raw) || trim($raw) === '') {
        json_response(array(
            'ok' => false,
            'error' => 'empty_json_body',
        ), 400);
        return null;
    }

    if (function_exists('xmark')) {
        xmark($raw);
    }

    $decoded = json_decode($raw, true);
    if (!is_array($decoded)) {
        json_response(array(
            'ok' => false,
            'error' => 'invalid_json',
            'json_error' => json_last_error_msg(),
        ), 400);
        return null;
    }

    return $decoded;
}

/**
 * @param array<string, mixed> $payload
 * @param array<string, string> $headers
 */
function json_response(array $payload, int $status = 200, array $headers = array()): void
{
    http_response_code($status);
    foreach ($headers as $name => $value) {
        header($name . ': ' . $value);
    }
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
}

function json_query_response(mysqli $db, string $category, string $sink, string $jsonPath, string $sql): void
{
    $res = $db->query($sql);
    if ($res === false) {
        json_response(array(
            'ok' => false,
            'category' => $category,
            'sink' => $sink,
            'vulnerable_json_path' => $jsonPath,
            'sql' => $sql,
            'db_error' => $db->error,
        ));
        return;
    }

    $rows = array();
    if ($res instanceof mysqli_result) {
        while ($row = $res->fetch_assoc()) {
            $rows[] = $row;
        }
    }

    json_response(array(
        'ok' => true,
        'category' => $category,
        'sink' => $sink,
        'vulnerable_json_path' => $jsonPath,
        'sql' => $sql,
        'rows' => $rows,
    ));
}

function json_fetch_response(string $url, string $jsonPath): void
{
    $context = stream_context_create(array(
        'http' => array('timeout' => 4, 'ignore_errors' => true),
        'ftp' => array('timeout' => 4),
    ));
    $body = @file_get_contents($url, false, $context);
    $headers = isset($http_response_header) && is_array($http_response_header) ? $http_response_header : array();

    json_response(array(
        'ok' => is_string($body),
        'category' => 'ssrf',
        'sink' => 'file_get_contents',
        'vulnerable_json_path' => $jsonPath,
        'url' => $url,
        'response_headers' => array_slice($headers, 0, 10),
        'body_preview' => is_string($body) ? substr($body, 0, 4000) : null,
        'fetch_failed' => !is_string($body),
    ));
}

function seed_database(mysqli $db): void
{
    static $seeded = false;
    if ($seeded) {
        return;
    }

    $schemaPath = dirname(__DIR__) . '/schema.sql';
    $schema = @file_get_contents($schemaPath);
    if (!is_string($schema) || trim($schema) === '') {
        return;
    }

    foreach (explode(";\n", $schema) as $statement) {
        $sql = trim($statement);
        if ($sql === '' || str_starts_with($sql, '--')) {
            continue;
        }
        @$db->query($sql);
    }
    $seeded = true;
}
