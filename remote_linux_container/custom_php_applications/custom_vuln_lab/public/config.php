<?php

declare(strict_types=1);

const CUSTOM_VULN_LAB_VERSION = '1.0.0';

function app_config(): array
{
    return array(
        'db_host' => (string) (getenv('CUSTOM_VULN_LAB_DB_HOST') ?: '127.0.0.1'),
        'db_port' => (int) (getenv('CUSTOM_VULN_LAB_DB_PORT') ?: '3306'),
        'db_name' => (string) (getenv('CUSTOM_VULN_LAB_DB_NAME') ?: 'custom_vuln_lab'),
        'db_user' => (string) (getenv('CUSTOM_VULN_LAB_DB_USER') ?: 'custom_vuln_lab_user'),
        'db_password' => (string) (getenv('CUSTOM_VULN_LAB_DB_PASSWORD') ?: 'synthetic-lab-database-only'),
        'site_name' => 'Custom Vulnerable Fuzzer Lab',
        'warning' => 'This application is intentionally vulnerable for authorized security testing only.',
        'upload_dir' => __DIR__ . '/uploads',
        'lfi_pages_dir' => __DIR__ . '/pages',
    );
}

function db_connect(bool $throwOnError = false): ?mysqli
{
    $cfg = app_config();
    mysqli_report(MYSQLI_REPORT_OFF);
    $db = @new mysqli(
        $cfg['db_host'],
        $cfg['db_user'],
        $cfg['db_password'],
        $cfg['db_name'],
        $cfg['db_port']
    );

    if ($db->connect_errno !== 0) {
        if ($throwOnError) {
            throw new RuntimeException('Database connection failed: ' . $db->connect_error);
        }
        return null;
    }

    $db->set_charset('utf8mb4');
    return $db;
}

function esc(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function h1(string $title): void
{
    echo '<h1>' . esc($title) . '</h1>';
}

function page_start(string $title): void
{
    $cfg = app_config();
    header('Content-Type: text/html; charset=utf-8');
    echo '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">';
    echo '<title>' . esc($title) . '</title>';
    echo '<style>body{font-family:Arial,sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:0}a{color:#7dd3fc}main{max-width:1100px;margin:0 auto;padding:20px}.panel{background:#111827;border:1px solid #334155;border-radius:8px;padding:14px;margin:0 0 12px}code,pre{background:#020617;border:1px solid #334155;border-radius:6px;padding:8px;display:block;overflow:auto}input,textarea,select,button{padding:8px;border-radius:6px;border:1px solid #475569;background:#020617;color:#e2e8f0}textarea{box-sizing:border-box;max-width:100%;width:100%}table{width:100%;border-collapse:collapse}th,td{border:1px solid #334155;padding:8px;text-align:left}th{background:#1e293b}.warn{background:#7f1d1d;color:#fee2e2;padding:10px;border-bottom:1px solid #ef4444}.top{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px}.pill{display:inline-block;padding:2px 8px;border:1px solid #475569;border-radius:999px;background:#1e293b;font-size:12px}</style>';
    echo '</head><body>';
    echo '<div class="warn"><strong>Warning:</strong> ' . esc($cfg['warning']) . '</div>';
    echo '<main>';
    echo '<div class="top">';
    echo '<a href="/">Home</a><a href="/catalog">Catalog</a><a href="/catalog.json">Catalog JSON</a><a href="/session/debug">Session Debug</a>';
    if (current_user() !== null) {
        echo '<span class="pill">Logged in as ' . esc((string) current_user()['username']) . '</span>';
        echo '<a href="/auth/logout">Logout</a>';
    } else {
        echo '<a href="/auth/login">Login</a>';
    }
    echo '</div>';
    h1($title);
}

function page_end(): void
{
    echo '<footer class="panel"><small>custom_vuln_lab v' . esc(CUSTOM_VULN_LAB_VERSION) . ' - intentionally vulnerable.</small></footer>';
    echo '</main></body></html>';
}

function current_user(): ?array
{
    if (!isset($_SESSION['user']) || !is_array($_SESSION['user'])) {
        return null;
    }

    return $_SESSION['user'];
}

function require_login(): void
{
    if (current_user() !== null) {
        return;
    }

    header('Location: /auth/login');
    exit;
}

function render_exploit_guide(string $routePath): void
{
    $guides = exploit_guides();
    if (!isset($guides[$routePath])) {
        return;
    }

    $guide = $guides[$routePath];
    echo '<div class="panel">';
    echo '<h2>How To Trigger / Exploit</h2>';
    echo '<p><strong>Vulnerable Situation:</strong> ' . esc((string) ($guide['vulnerable_situation'] ?? '')) . '</p>';

    $vars = $guide['required_variables'] ?? array();
    if (is_array($vars) && $vars !== array()) {
        echo '<h3>Required Variables</h3>';
        echo '<table><thead><tr><th>Variable</th><th>Location</th><th>Required</th><th>Example</th><th>Why It Matters</th></tr></thead><tbody>';
        foreach ($vars as $row) {
            if (!is_array($row)) {
                continue;
            }
            echo '<tr>';
            echo '<td><code>' . esc((string) ($row['name'] ?? '')) . '</code></td>';
            echo '<td>' . esc((string) ($row['location'] ?? '')) . '</td>';
            echo '<td>' . esc((string) ($row['required'] ?? '')) . '</td>';
            echo '<td><code>' . esc((string) ($row['example'] ?? '')) . '</code></td>';
            echo '<td>' . esc((string) ($row['notes'] ?? '')) . '</td>';
            echo '</tr>';
        }
        echo '</tbody></table>';
    }

    $steps = $guide['exploit_steps'] ?? array();
    if (is_array($steps) && $steps !== array()) {
        echo '<h3>Exploit Workflow</h3><ol>';
        foreach ($steps as $step) {
            echo '<li>' . esc((string) $step) . '</li>';
        }
        echo '</ol>';
    }

    $signals = $guide['expected_fuzzer_signal'] ?? array();
    if (is_array($signals) && $signals !== array()) {
        echo '<h3>Expected Fuzzer Signal</h3><ul>';
        foreach ($signals as $signal) {
            echo '<li>' . esc((string) $signal) . '</li>';
        }
        echo '</ul>';
    }

    echo '</div>';
}

function auto_json_guide(string $situation, string $jsonPath, string $example, string $signal): array
{
    return array(
        'vulnerable_situation' => 'A crawlable GET page automatically sends JSON on page load. ' . $situation,
        'required_variables' => array(
            array('name' => $jsonPath, 'location' => 'Auto JSON body', 'required' => 'No', 'example' => $example, 'notes' => 'Default payload is editable on the auto page and is posted with Content-Type: application/json.'),
        ),
        'exploit_steps' => array('Visit the auto page in a JavaScript-capable crawler.', 'Observe the page-load fetch to the target JSON API and inspect the inline response.'),
        'expected_fuzzer_signal' => array($signal, 'Crawler discovers a GET page that silently issues JSON POST traffic.'),
    );
}

function auto_catalog_entry(string $path, string $targetCategory, string $targetApi, string $shapeComplexity, string $description, string $expectedSignal): array
{
    return array(
        'path' => $path,
        'method' => 'GET',
        'category' => 'auto',
        'target_category' => $targetCategory,
        'target_api' => $targetApi,
        'trigger_event' => 'page_load',
        'request_body_format' => 'json',
        'shape_complexity' => $shapeComplexity,
        'difficulty' => $shapeComplexity === 'easy' ? 'basic' : 'intermediate',
        'auth_required' => false,
        'description' => $description,
        'expected_signal' => $expectedSignal,
    );
}

function exploit_guides(): array
{
    return array(
        '/xss/reflected' => array(
            'vulnerable_situation' => 'User-controlled input is written directly into HTML body content without output encoding.',
            'required_variables' => array(
                array('name' => 'input', 'location' => 'GET/POST', 'required' => 'No', 'example' => '<script>alert(1)</script>', 'notes' => 'Injected directly into the DOM response body.'),
            ),
            'exploit_steps' => array(
                'Send a payload in input that executes in an HTML body context.',
                'Load the response in a browser-capable client to observe script execution.',
            ),
            'expected_fuzzer_signal' => array('Reflected payload appears unescaped in response body.', 'Script-capable payload executes client-side.'),
        ),
        '/xss/attr' => array(
            'vulnerable_situation' => 'User input is inserted into an HTML attribute without escaping, enabling attribute breakout.',
            'required_variables' => array(
                array('name' => 'input', 'location' => 'GET/POST', 'required' => 'No', 'example' => '" onmouseover="alert(1)', 'notes' => 'Breaks out of value attribute and injects event handler.'),
            ),
            'exploit_steps' => array('Inject an attribute-breaking payload.', 'Trigger the injected event in the rendered page.'),
            'expected_fuzzer_signal' => array('Response contains malformed or attacker-controlled attribute structure.'),
        ),
        '/xss/js' => array(
            'vulnerable_situation' => 'Untrusted input is concatenated into a JavaScript string literal.',
            'required_variables' => array(
                array('name' => 'input', 'location' => 'GET/POST', 'required' => 'No', 'example' => "';alert(1);//", 'notes' => 'Closes JS string and appends attacker statements.'),
            ),
            'exploit_steps' => array('Inject string-breaking payload.', 'Confirm JS parser accepts attacker statements.'),
            'expected_fuzzer_signal' => array('Reflected payload appears in script block.', 'Client-side code execution or JS syntax anomaly.'),
        ),
        '/xss/stored' => array(
            'vulnerable_situation' => 'Comment content is persisted and rendered without output encoding.',
            'required_variables' => array(
                array('name' => 'body', 'location' => 'POST form field', 'required' => 'Yes', 'example' => '<svg/onload=alert(1)>', 'notes' => 'Stored payload is replayed to later visitors.'),
            ),
            'exploit_steps' => array('POST malicious comment body.', 'Reload or revisit page to trigger persisted payload.'),
            'expected_fuzzer_signal' => array('Payload remains in storage and reappears in subsequent responses.'),
        ),
        '/xss/filtered' => array(
            'vulnerable_situation' => 'Application applies a naive blacklist and then injects the result into HTML context.',
            'required_variables' => array(
                array('name' => 'input', 'location' => 'GET/POST', 'required' => 'No', 'example' => '<svg/onload=alert(1)>', 'notes' => 'Blacklist only strips script and quotes, leaving many vectors.'),
            ),
            'exploit_steps' => array('Provide a payload that survives keyword/quote stripping.', 'Verify filtered payload still creates executable markup.'),
            'expected_fuzzer_signal' => array('Filtered output still contains attacker-controlled executable context.'),
        ),
        '/sqli/error' => array(
            'vulnerable_situation' => 'Numeric id is concatenated directly into SQL without parameterization.',
            'required_variables' => array(
                array('name' => 'id', 'location' => 'GET', 'required' => 'No', 'example' => "1'", 'notes' => 'Malformed SQL can surface DB errors.'),
            ),
            'exploit_steps' => array('Inject SQL metacharacters into id.', 'Observe DB error message or stack hints in response.'),
            'expected_fuzzer_signal' => array('Response includes SQL error text from database engine.'),
        ),
        '/api/json/sqli/error' => array(
            'vulnerable_situation' => 'JSON body fields are decoded and concatenated into SQL without parameterization.',
            'required_variables' => array(
                array('name' => 'lookup.id', 'location' => 'JSON body', 'required' => 'No', 'example' => "1'", 'notes' => 'Nested JSON scalar is inserted directly into WHERE clause.'),
                array('name' => 'options.limit', 'location' => 'JSON body', 'required' => 'No', 'example' => '10', 'notes' => 'Limit is also concatenated to exercise multiple JSON leaf paths.'),
            ),
            'exploit_steps' => array('POST application/json with lookup.id set to a SQL metacharacter payload.', 'Observe JSON response with SQL error text or altered row output.'),
            'expected_fuzzer_signal' => array('JSON-only input reaches SQL sink and changes query behavior.'),
        ),
        '/sqli/union' => array(
            'vulnerable_situation' => 'Query result columns can be extended by UNION when id is attacker-controlled.',
            'required_variables' => array(
                array('name' => 'id', 'location' => 'GET', 'required' => 'No', 'example' => '-1 UNION SELECT 1,2,3', 'notes' => 'Three-column projection expected.'),
            ),
            'exploit_steps' => array('Determine column count.', 'Inject UNION SELECT to append controlled row data.'),
            'expected_fuzzer_signal' => array('Unexpected rows/values appear in response table.'),
        ),
        '/sqli/blind-bool' => array(
            'vulnerable_situation' => 'Boolean condition is directly evaluated inside SQL WHERE clause.',
            'required_variables' => array(
                array('name' => 'id', 'location' => 'GET', 'required' => 'No', 'example' => '1 AND 1=2', 'notes' => 'Changes logical condition without explicit SQL errors.'),
            ),
            'exploit_steps' => array('Send paired true/false boolean payloads.', 'Compare response message differences.'),
            'expected_fuzzer_signal' => array('Stable response-differential between boolean true and false payloads.'),
        ),
        '/sqli/blind-time' => array(
            'vulnerable_situation' => 'Attacker input is embedded into SQL predicate that can execute delay primitives.',
            'required_variables' => array(
                array('name' => 'id', 'location' => 'GET', 'required' => 'No', 'example' => '1 OR IF(1=1,SLEEP(3),0)', 'notes' => 'Delay confirms server-side SQL execution path.'),
            ),
            'exploit_steps' => array('Send baseline request.', 'Send timing payload and compare elapsed time.'),
            'expected_fuzzer_signal' => array('Consistent response latency increase for delay payload.'),
        ),
        '/sqli/constrained' => array(
            'vulnerable_situation' => 'Username filter removes a blacklist subset but still uses string concatenation in SQL.',
            'required_variables' => array(
                array('name' => 'id', 'location' => 'GET', 'required' => 'No', 'example' => "alice'OR'1'='1", 'notes' => 'Bypasses simplistic blacklist assumptions.'),
            ),
            'exploit_steps' => array('Craft payload resilient to stripped keywords/whitespace.', 'Validate that altered SQL still changes result set.'),
            'expected_fuzzer_signal' => array('Query behavior changes despite input filtering layer.'),
        ),
        '/sqli/login' => array(
            'vulnerable_situation' => 'Login query concatenates username/password into WHERE clause directly.',
            'required_variables' => array(
                array('name' => 'username', 'location' => 'POST', 'required' => 'Yes', 'example' => "' OR '1'='1", 'notes' => 'Classic auth-bypass injection vector.'),
                array('name' => 'password', 'location' => 'POST', 'required' => 'Yes', 'example' => 'anything', 'notes' => 'Still included in vulnerable SQL string.'),
            ),
            'exploit_steps' => array('Submit SQLi payload in username field.', 'Observe authentication success without valid credentials.'),
            'expected_fuzzer_signal' => array('Authenticated state for invalid credentials.'),
        ),
        '/csrf/change-email' => array(
            'vulnerable_situation' => 'Authenticated state-change endpoint lacks CSRF token validation.',
            'required_variables' => array(
                array('name' => 'email', 'location' => 'POST', 'required' => 'Yes', 'example' => 'victim+csrf@example.test', 'notes' => 'Any cross-site form post can mutate account email.'),
            ),
            'exploit_steps' => array('Authenticate victim session.', 'Send forged POST from foreign origin context.'),
            'expected_fuzzer_signal' => array('State mutation succeeds with only session cookie present.'),
        ),
        '/csrf/transfer' => array(
            'vulnerable_situation' => 'Money transfer endpoint accepts POST actions without CSRF verification.',
            'required_variables' => array(
                array('name' => 'to_user_id', 'location' => 'POST', 'required' => 'Yes', 'example' => '2', 'notes' => 'Destination account identifier.'),
                array('name' => 'amount', 'location' => 'POST', 'required' => 'Yes', 'example' => '50', 'notes' => 'Amount to transfer from victim account.'),
            ),
            'exploit_steps' => array('Log in as any seeded user.', 'Submit forged transfer request from attacker-controlled page.'),
            'expected_fuzzer_signal' => array('Account balances change without anti-CSRF token.'),
        ),
        '/csrf/weak-token' => array(
            'vulnerable_situation' => 'CSRF token is deterministic and derived from predictable user id.',
            'required_variables' => array(
                array('name' => 'email', 'location' => 'POST', 'required' => 'Yes', 'example' => 'new@example.test', 'notes' => 'Target mutation value.'),
                array('name' => 'csrf_token', 'location' => 'POST', 'required' => 'Yes', 'example' => 'md5(user_id)', 'notes' => 'Predictable token allows bypass.'),
            ),
            'exploit_steps' => array('Derive token from known user id scheme.', 'Submit forged request using predicted token.'),
            'expected_fuzzer_signal' => array('Token bypass works without reading server-generated secret.'),
        ),
        '/rce/system' => array(
            'vulnerable_situation' => 'User input is passed directly into system() command execution.',
            'required_variables' => array(
                array('name' => 'cmd', 'location' => 'GET', 'required' => 'No', 'example' => 'id', 'notes' => 'Executed by OS shell.'),
            ),
            'exploit_steps' => array('Send benign proof command first.', 'Escalate to chained command payloads where allowed.'),
            'expected_fuzzer_signal' => array('Response contains transformed command output from executed process.'),
        ),
        '/rce/filtered' => array(
            'vulnerable_situation' => 'Application applies weak blacklist before shell_exec().',
            'required_variables' => array(
                array('name' => 'cmd', 'location' => 'GET', 'required' => 'No', 'example' => 'whoami', 'notes' => 'Blacklisted characters are removed, not safely escaped.'),
            ),
            'exploit_steps' => array('Probe blacklist behavior and output.', 'Craft payload that survives removals but still executes meaningful command.'),
            'expected_fuzzer_signal' => array('Execution output despite filtering layer.'),
        ),
        '/rce/eval' => array(
            'vulnerable_situation' => 'Untrusted code string is executed via eval().',
            'required_variables' => array(
                array('name' => 'code', 'location' => 'GET', 'required' => 'No', 'example' => 'echo phpversion();', 'notes' => 'Arbitrary PHP execution context.'),
            ),
            'exploit_steps' => array('Inject harmless PHP expression to prove execution.', 'Expand to file/process operations for deeper checks.'),
            'expected_fuzzer_signal' => array('Attacker-provided PHP code output appears in response.'),
        ),
        '/api/json/rce/system' => array(
            'vulnerable_situation' => 'Nested JSON command field is passed directly into system().',
            'required_variables' => array(
                array('name' => 'task.command', 'location' => 'JSON body', 'required' => 'No', 'example' => 'id', 'notes' => 'Decoded JSON scalar is executed by OS shell.'),
                array('name' => 'metadata.source', 'location' => 'JSON body', 'required' => 'No', 'example' => 'json-lab', 'notes' => 'Non-sink metadata field helps scanners preserve benign context.'),
            ),
            'exploit_steps' => array('POST application/json with task.command set to a benign proof command.', 'Confirm command output appears in JSON response.'),
            'expected_fuzzer_signal' => array('JSON-only input reaches command execution sink.'),
        ),
        '/ssrf/fetch' => array(
            'vulnerable_situation' => 'User-controlled URL is fetched server-side with file_get_contents().',
            'required_variables' => array(
                array('name' => 'url', 'location' => 'GET', 'required' => 'No', 'example' => 'http://127.0.0.1:9/', 'notes' => 'Target may include internal services.'),
            ),
            'exploit_steps' => array('Submit external URL baseline.', 'Target internal/loopback addresses to verify SSRF reachability.'),
            'expected_fuzzer_signal' => array('Server performs outbound request to attacker-controlled target.'),
        ),
        '/ssrf/weak-filter' => array(
            'vulnerable_situation' => 'Localhost blocklist checks a limited string set and is bypassable.',
            'required_variables' => array(
                array('name' => 'url', 'location' => 'GET', 'required' => 'No', 'example' => 'http://127.1:9/', 'notes' => 'Alternate host representations bypass naive filter.'),
            ),
            'exploit_steps' => array('Trigger blocked literal localhost payload.', 'Bypass with alternate loopback notation or host forms.'),
            'expected_fuzzer_signal' => array('Internal fetch works despite host filter intent.'),
        ),
        '/ssrf/redirect' => array(
            'vulnerable_situation' => 'Fetcher follows redirects, enabling chained access to internal resources.',
            'required_variables' => array(
                array('name' => 'url', 'location' => 'GET', 'required' => 'No', 'example' => 'http://attacker/redirect?next=http://127.0.0.1:9/', 'notes' => 'Redirect chain can pivot into restricted network targets.'),
            ),
            'exploit_steps' => array('Point to redirector endpoint.', 'Observe final fetch target and body after redirect traversal.'),
            'expected_fuzzer_signal' => array('Server follows attacker-controlled redirect chain to internal URI.'),
        ),
        '/file/lfi' => array(
            'vulnerable_situation' => 'page parameter is concatenated into include path without canonicalization.',
            'required_variables' => array(
                array('name' => 'page', 'location' => 'GET', 'required' => 'No', 'example' => '../../../../etc/hosts', 'notes' => 'Traversal escapes intended pages directory.'),
            ),
            'exploit_steps' => array('Test local template name first.', 'Send traversal payload to include sensitive local file paths.'),
            'expected_fuzzer_signal' => array('Local file content or include warnings reveal disclosure vector.'),
        ),
        '/file/lfi-constrained' => array(
            'vulnerable_situation' => 'Naive traversal sanitation strips a few patterns but still trusts user path input.',
            'required_variables' => array(
                array('name' => 'page', 'location' => 'GET', 'required' => 'No', 'example' => '....//....//etc/passwd', 'notes' => 'Alternative traversal forms may bypass replacement.'),
            ),
            'exploit_steps' => array('Observe sanitized value output.', 'Mutate encoding and separators to bypass pattern stripping.'),
            'expected_fuzzer_signal' => array('Sanitized path still resolves to unintended local file.'),
        ),
        '/file/rfi' => array(
            'vulnerable_situation' => 'Application includes attacker-supplied URL/stream wrapper with allow_url_include enabled.',
            'required_variables' => array(
                array('name' => 'url', 'location' => 'GET', 'required' => 'No', 'example' => 'php://filter/resource=/etc/hosts', 'notes' => 'Remote wrappers and stream wrappers become code/data include surface.'),
            ),
            'exploit_steps' => array('Start with safe wrapper proving include control.', 'Use remote payload hosting where environment allows.'),
            'expected_fuzzer_signal' => array('Included remote/wrapper content appears in server response.'),
        ),
        '/api/json/file/lfi' => array(
            'vulnerable_situation' => 'Nested JSON file path material is concatenated into local include/read paths.',
            'required_variables' => array(
                array('name' => 'file.page', 'location' => 'JSON body', 'required' => 'No', 'example' => 'home', 'notes' => 'Controls the path fragment below the pages directory.'),
                array('name' => 'options.suffix', 'location' => 'JSON body', 'required' => 'No', 'example' => '.php', 'notes' => 'Controls appended suffix and can be set empty for traversal experiments.'),
            ),
            'exploit_steps' => array('POST application/json with file.page and options.suffix fields.', 'Mutate path material to traverse or disclose unintended local files.'),
            'expected_fuzzer_signal' => array('JSON-only input reaches local file include/read sink.'),
        ),
        '/idor/order' => array(
            'vulnerable_situation' => 'Object lookup trusts user-supplied id without enforcing owner check in vuln mode.',
            'required_variables' => array(
                array('name' => 'id', 'location' => 'GET', 'required' => 'No', 'example' => '2', 'notes' => 'Switching ids can reveal other users records.'),
                array('name' => 'mode', 'location' => 'GET', 'required' => 'No', 'example' => 'vuln', 'notes' => 'safe mode demonstrates expected ownership constraint.'),
            ),
            'exploit_steps' => array('Log in as seeded user.', 'Iterate order ids and observe cross-tenant disclosure in vuln mode.'),
            'expected_fuzzer_signal' => array('Authenticated user can read another owner order object.'),
        ),
        '/upload/shell' => array(
            'vulnerable_situation' => 'Upload filter explicitly allows executable extensions such as .php and .phtml.',
            'required_variables' => array(
                array('name' => 'payload', 'location' => 'multipart file field', 'required' => 'Yes', 'example' => 'shell.php', 'notes' => 'Uploaded file is placed in web-accessible uploads directory.'),
            ),
            'exploit_steps' => array('Upload executable payload with allowed extension.', 'Request uploaded file URL to verify execution or disclosure.'),
            'expected_fuzzer_signal' => array('Server accepts and exposes executable upload artifact.'),
        ),
        '/redirect' => array(
            'vulnerable_situation' => 'next parameter is used as redirect target with no allowlist/validation.',
            'required_variables' => array(
                array('name' => 'next', 'location' => 'GET', 'required' => 'Yes', 'example' => 'https://example.org', 'notes' => 'Fully attacker-controlled redirect destination.'),
                array('name' => 'go', 'location' => 'GET', 'required' => 'Conditional', 'example' => '1', 'notes' => 'Set go=1 to execute redirect from this documentation page.'),
            ),
            'exploit_steps' => array('Set a destination in next.', 'Trigger redirect execution and confirm 302 Location header.'),
            'expected_fuzzer_signal' => array('Response issues 302 redirect to attacker-supplied absolute URL.'),
        ),
        '/auto/rce/system' => array(
            'vulnerable_situation' => 'A crawlable GET page automatically sends a JSON POST whose nested command field reaches system().',
            'required_variables' => array(
                array('name' => 'task.command', 'location' => 'Auto JSON body', 'required' => 'No', 'example' => 'printf auto_rce_ok', 'notes' => 'Executed by the API when the page-load fetch fires.'),
            ),
            'exploit_steps' => array('Visit the auto page in a JavaScript-capable crawler.', 'Observe the page-load fetch to /api/json/rce/system and command output in the response panel.'),
            'expected_fuzzer_signal' => array('Crawler discovers a GET page that silently issues JSON POST traffic.', 'Response includes command output from the JSON-controlled sink.'),
        ),
        '/auto/file/lfi' => array(
            'vulnerable_situation' => 'A crawlable GET page automatically sends JSON path material to a local include/read sink.',
            'required_variables' => array(
                array('name' => 'file.page', 'location' => 'Auto JSON body', 'required' => 'No', 'example' => 'home', 'notes' => 'Controls included page fragment.'),
                array('name' => 'options.suffix', 'location' => 'Auto JSON body', 'required' => 'No', 'example' => '.php', 'notes' => 'Controls appended suffix.'),
            ),
            'exploit_steps' => array('Visit the auto page with JavaScript enabled.', 'Mutate the displayed JSON path values to test traversal/file disclosure.'),
            'expected_fuzzer_signal' => array('Page-load JSON POST reaches include and file_get_contents sinks.'),
        ),
        '/auto/sqli/error' => array(
            'vulnerable_situation' => 'A crawlable GET page automatically sends a JSON SQLi payload that is concatenated into mysqli::query.',
            'required_variables' => array(
                array('name' => 'lookup.id', 'location' => 'Auto JSON body', 'required' => 'No', 'example' => "1'", 'notes' => 'Default value intentionally triggers SQL error behavior.'),
                array('name' => 'options.limit', 'location' => 'Auto JSON body', 'required' => 'No', 'example' => '10', 'notes' => 'Second JSON leaf also reaches query text.'),
            ),
            'exploit_steps' => array('Visit the page to trigger the automatic JSON POST.', 'Inspect the response panel for SQL text and DB error details.'),
            'expected_fuzzer_signal' => array('Page-load JSON request causes SQL error or row differential.'),
        ),
        '/auto/ssrf/fetch' => array(
            'vulnerable_situation' => 'A crawlable GET page automatically sends a JSON-controlled URL to a server-side fetch sink.',
            'required_variables' => array(
                array('name' => 'request.url', 'location' => 'Auto JSON body', 'required' => 'No', 'example' => 'data://text/plain,auto_ssrf_fetch_ok', 'notes' => 'Default is deterministic; mutate to HTTP/internal URLs for SSRF fuzzing.'),
            ),
            'exploit_steps' => array('Visit the page and observe the automatic JSON POST to the SSRF API.', 'Replace request.url with internal HTTP targets to exercise server-side reachability.'),
            'expected_fuzzer_signal' => array('Server-side fetch preview appears in JSON response.'),
        ),
        '/auto/xss/stored-comment' => array(
            'vulnerable_situation' => 'A crawlable GET page automatically stores a JSON-controlled comment body that later renders without encoding.',
            'required_variables' => array(
                array('name' => 'comment.body', 'location' => 'Auto JSON body', 'required' => 'No', 'example' => "AUTO_JSON_XSS:<svg/onload=alert('auto-json-xss')>", 'notes' => 'Persisted and rendered by /xss/stored.'),
                array('name' => 'actor.user_id', 'location' => 'Auto JSON body', 'required' => 'No', 'example' => '1', 'notes' => 'Controls attributed user id for the stored record.'),
            ),
            'exploit_steps' => array('Visit the auto page to store the comment through JSON fetch.', 'Open /xss/stored to observe the persisted payload render path.'),
            'expected_fuzzer_signal' => array('Stored record id is returned and payload appears on the stored comments route.'),
        ),
        '/auto/idor/order' => array(
            'vulnerable_situation' => 'A crawlable GET page automatically sends a JSON object id lookup that omits owner enforcement by default.',
            'required_variables' => array(
                array('name' => 'actor.user_id', 'location' => 'Auto JSON body', 'required' => 'No', 'example' => '1', 'notes' => 'Simulated caller identity.'),
                array('name' => 'lookup.order_id', 'location' => 'Auto JSON body', 'required' => 'No', 'example' => '2', 'notes' => 'Default reads another seeded user order.'),
            ),
            'exploit_steps' => array('Visit the page to trigger the automatic order lookup.', 'Compare actor.user_id with returned owner_user_id for cross-user disclosure.'),
            'expected_fuzzer_signal' => array('Response returns an order owned by a different user id.'),
        ),
        '/auto/state/change-email' => array(
            'vulnerable_situation' => 'A crawlable GET page automatically sends a JSON state-changing email update with no auth or CSRF-style validation.',
            'required_variables' => array(
                array('name' => 'user.id', 'location' => 'Auto JSON body', 'required' => 'No', 'example' => '1', 'notes' => 'Controls the target user record.'),
                array('name' => 'profile.email', 'location' => 'Auto JSON body', 'required' => 'No', 'example' => 'alice+auto-json@example.test', 'notes' => 'New value written to the database.'),
            ),
            'exploit_steps' => array('Visit the auto page to trigger the automatic state-changing POST.', 'Inspect the JSON response for SQL text and affected row count.'),
            'expected_fuzzer_signal' => array('Database row changes from a page-load JSON request.'),
        ),
        '/auto/session/set-cookie' => array(
            'vulnerable_situation' => 'A crawlable GET page automatically sends JSON cookie material to an insecure setcookie() sink.',
            'required_variables' => array(
                array('name' => 'cookie.name', 'location' => 'Auto JSON body', 'required' => 'No', 'example' => 'auto_json_token', 'notes' => 'Controls cookie name.'),
                array('name' => 'cookie.value', 'location' => 'Auto JSON body', 'required' => 'No', 'example' => 'demo-auto-json', 'notes' => 'Controls cookie value.'),
            ),
            'exploit_steps' => array('Visit the page so JavaScript posts the cookie JSON on load.', 'Inspect the Set-Cookie response and inline JSON flags.'),
            'expected_fuzzer_signal' => array('Set-Cookie header has attacker-controlled value and insecure attributes.'),
        ),
        '/auto/rce/argv-array' => auto_json_guide('Array-based command execution where exec.binary and exec.argv[] are joined into a shell command.', 'exec.binary + exec.argv[]', 'printf + auto_rce_array_ok', 'Page-load JSON POST reaches system() through an argv-style shape.'),
        '/auto/rce/workflow-step' => auto_json_guide('Workflow-style command execution where the run step contains the command sink.', 'workflow.steps[1].params.command', 'printf auto_rce_workflow_ok', 'Deep workflow JSON path reaches system().'),
        '/auto/sqli/search-filter' => auto_json_guide('Nested search criteria are concatenated into a SQL WHERE string.', 'search.criteria.username', "alice' OR '1'='1", 'Nested JSON search field changes SQL row output.'),
        '/auto/sqli/sort-clause' => auto_json_guide('Grid sort field and direction are concatenated into an ORDER BY clause.', 'grid.sort.field + grid.sort.direction', 'id DESC', 'Sort metadata reaches SQL query text.'),
        '/auto/sqli/batch-lookup' => auto_json_guide('A selected batch request id is concatenated into SQL.', 'requests[options.use_index].id', '2 OR 1=1', 'Array-selected JSON value changes SQL row output.'),
        '/auto/file/lang-include' => auto_json_guide('Locale and template fields are joined into an include/read path.', 'view.locale + view.template', '../pages/home', 'Nested path fields reach include and file_get_contents.'),
        '/auto/file/path-parts' => auto_json_guide('Array path parts and extension are joined into a local file read path.', 'document.path_parts[] + document.extension', '["home"] + php', 'Array path material reaches file_get_contents.'),
        '/auto/file/write-json' => auto_json_guide('JSON artifact name and content are written to a web-accessible file.', 'artifact.name + artifact.content', 'auto_json_write.json', 'Page-load JSON POST writes attacker-controlled file content.'),
        '/auto/ssrf/webhook-basic' => auto_json_guide('A top-level webhook URL is fetched server-side.', 'webhook_url', 'data://text/plain,auto_ssrf_webhook_ok', 'Scalar JSON URL reaches file_get_contents.'),
        '/auto/ssrf/events-callback' => auto_json_guide('A deeply nested event callback URL is fetched server-side.', 'events[1].delivery.callback.href', 'data://text/plain,auto_ssrf_event_ok', 'Deep callback JSON URL reaches file_get_contents.'),
        '/auto/xss/profile-card' => auto_json_guide('Profile fields are concatenated into an HTML card without output encoding.', 'profile.display_name', '<img src=x onerror=alert(1)>', 'JSON-controlled HTML appears in response preview.'),
        '/auto/xss/dom-fragment' => auto_json_guide('Widget HTML is returned for a client innerHTML contract.', 'widgets[0].html', '<svg/onload=alert(1)>', 'Array-held HTML fragment is returned as DOM sink material.'),
        '/auto/idor/account-balance' => auto_json_guide('Account user id is read from JSON without matching it to the actor.', 'resource.account.user_id', '2 while actor.user_id is 1', 'Response returns another user account balance.'),
        '/auto/auth/mass-assignment-role' => auto_json_guide('Profile role is accepted in a broad update object and written to users.role.', 'user.profile.role', 'admin', 'JSON role field changes a user authorization attribute.'),
        '/auto/state/transfer-log' => auto_json_guide('Transfer fields are accepted from JSON and inserted without auth or CSRF checks.', 'transfer.to_user_id + transfer.amount', '2 + 7.77', 'Page-load JSON POST creates a transfer log record.'),
        '/auto/deserialization/php-object' => auto_json_guide('Serialized PHP object text is taken from JSON and passed to unserialize().', 'payload.serialized', 'O:8:"stdClass"...', 'Response reports unserialized object type and preview.'),
        '/auto/cors/reflect-origin-json' => auto_json_guide('JSON-controlled origin value is reflected into Access-Control-Allow-Origin.', 'client.origin', 'https://attacker.example.test', 'Response reflects attacker origin with credentials enabled.'),
        '/auto/rce/template-eval' => auto_json_guide('PHP template code is taken from JSON and evaluated server-side.', 'template.php', 'echo "auto_eval_template_ok";', 'Template JSON reaches eval().'),
        '/auto/rce/env-chain' => auto_json_guide('A command is hidden in runtime env-style JSON and passed to shell_exec().', 'runtime.env.COMMAND', 'printf auto_rce_env_ok', 'Metadata-disguised JSON reaches shell_exec().'),
        '/auto/sqli/graphql-user' => auto_json_guide('GraphQL-like variables are concatenated into a SQL user lookup.', 'operation.variables.userId', '1 OR 1=1', 'GraphQL-style JSON variable changes SQL rows.'),
        '/auto/sqli/report-range' => auto_json_guide('Report range metadata is concatenated into a SQL status filter.', 'report.filters.range.end', "paid' OR '1'='1", 'Report filter JSON changes SQL rows.'),
        '/auto/sqli/ids-array' => auto_json_guide('Array elements are joined into a SQL IN clause without validation.', 'ids[]', '1) OR 1=1 --', 'Array JSON changes SQL predicate behavior.'),
        '/auto/sqli/json-operator' => auto_json_guide('Field/operator/value JSON objects are converted into a dynamic SQL predicate.', 'filters[0].field + filters[0].operator + filters[0].value', "username = alice' OR '1'='1", 'Dynamic predicate JSON changes SQL rows.'),
        '/auto/file/base64-read' => auto_json_guide('Base64 path material is decoded and used for a local file read.', 'blob.encoded_path', 'aG9tZS5waHA=', 'Encoded JSON path reaches file_get_contents.'),
        '/auto/file/theme-asset' => auto_json_guide('Theme metadata is joined into a local asset path.', 'ui.theme.name + ui.theme.asset', '../pages/help.php', 'Theme JSON path reaches file_get_contents.'),
        '/auto/file/temp-cleanup' => auto_json_guide('Cleanup target JSON is joined into a file path and unlinked.', 'cleanup.targets[0]', 'auto_cleanup_marker.txt', 'Array cleanup target reaches unlink().'),
        '/auto/ssrf/oembed-url' => auto_json_guide('Nested oEmbed endpoint JSON is fetched server-side.', 'preview.oembed.endpoint', 'data://text/plain,auto_ssrf_oembed_ok', 'oEmbed endpoint JSON reaches file_get_contents.'),
        '/auto/ssrf/openapi-server' => auto_json_guide('OpenAPI server metadata is fetched server-side.', 'spec.servers[0].url', 'data://text/plain,auto_ssrf_openapi_ok', 'OpenAPI server JSON reaches file_get_contents.'),
        '/auto/ssrf/avatar-proxy' => auto_json_guide('Avatar proxy URL inside an array of users is fetched server-side.', 'users[0].avatar.url', 'data://text/plain,auto_ssrf_avatar_ok', 'Array object URL reaches file_get_contents.'),
        '/auto/xss/markdown-preview' => auto_json_guide('Markdown body JSON is rendered into an unsafe HTML preview.', 'markdown.body', '<img src=x onerror=alert(1)>', 'Markdown JSON appears in HTML preview.'),
        '/auto/xss/svg-avatar' => auto_json_guide('SVG text from JSON is accepted as avatar markup.', 'asset.svg', '<svg onload="alert(1)">', 'SVG JSON appears in render preview.'),
        '/auto/xss/json-error-message' => auto_json_guide('Error message JSON is concatenated into an HTML error banner.', 'errors[0].message', '<marquee onstart=alert(1)>', 'Error-array JSON appears in HTML preview.'),
        '/auto/idor/invoice-export' => auto_json_guide('Invoice export id is read from JSON without owner enforcement.', 'export.invoice_id', '2 while actor.user_id is 1', 'Invoice/order owned by another user is returned.'),
        '/auto/idor/team-settings' => auto_json_guide('Team member id is read from JSON without membership enforcement.', 'team.members[0].user_id', '3 while actor.user_id is 1', 'Another user settings row is returned.'),
        '/auto/auth/debug-impersonate' => auto_json_guide('Debug impersonation JSON assigns the session user without authorization.', 'debug.impersonate.user_id', '3', 'Session user changes to the requested account.'),
        '/auto/auth/password-reset-token' => auto_json_guide('Password reset token is generated predictably from a JSON email and disclosed.', 'account.email', 'alice@example.test', 'Predictable reset token is returned.'),
        '/auto/state/feature-flag' => auto_json_guide('Feature flag JSON is written as trusted tenant state.', 'flags[0].name + flags[0].enabled', 'admin_console=true', 'Feature flag state artifact is written.'),
        '/auto/state/cart-price' => auto_json_guide('Cart price JSON is trusted when computing the server total.', 'cart.items[0].unit_price', '0.01', 'Client-controlled price becomes trusted total.'),
        '/auto/deserialization/base64-object' => auto_json_guide('Base64-encoded serialized object JSON is decoded and passed to unserialize().', 'payload.b64', 'base64 serialized stdClass', 'Encoded serialized JSON reaches unserialize().'),
        '/auto/redirect/json-next' => auto_json_guide('Navigation target JSON is used as a Location header.', 'navigation.next', 'https://example.org/auto-json-redirect', 'JSON-controlled redirect target is emitted.'),
        '/auto/cors/preflight-cache' => auto_json_guide('CORS policy arrays in JSON are reflected into preflight-related headers.', 'policy.origins[0] + policy.headers[]', 'https://evil-cache.example.test', 'CORS origin, headers, and max-age are reflected.'),
        '/auto/rce/header-command' => auto_json_guide('A command is disguised inside request header metadata and executed server-side.', 'request.headers.X-Command', 'printf auto_rce_header_ok', 'Header-map JSON reaches system().'),
        '/auto/rce/task-matrix' => auto_json_guide('A command is hidden inside a matrix row/cell structure and executed server-side.', 'matrix.rows[1].cells.command', 'printf auto_rce_matrix_ok', 'Matrix-cell JSON reaches shell_exec().'),
        '/auto/sqli/join-fragment' => auto_json_guide('A JSON join fragment is appended to a SQL JOIN condition.', 'query.join.on_extra', 'OR 1=1', 'JOIN metadata changes SQL row shape.'),
        '/auto/sqli/having-metric' => auto_json_guide('Analytics metric JSON becomes a SQL HAVING clause.', 'analytics.metrics[0].having', 'COUNT(*) >= 0 OR 1=1', 'Metric JSON changes grouped query results.'),
        '/auto/sqli/limit-offset' => auto_json_guide('Pagination metadata is concatenated into a SQL LIMIT/OFFSET fragment.', 'page.limit + page.offset', '10 + 0 OR 1=1', 'Pagination JSON reaches SQL syntax.'),
        '/auto/sqli/json-search-doc' => auto_json_guide('A document-like search filter is concatenated into a SQL LIKE clause.', 'document.sections[0].filters.term', "%' OR '1'='1", 'Document filter JSON changes SQL rows.'),
        '/auto/file/archive-extract' => auto_json_guide('Archive entry names from JSON are written without traversal validation.', 'archive.entries[0].path', 'auto_archive/../auto_archive_pwn.txt', 'Archive entry path reaches file_put_contents.'),
        '/auto/file/log-read' => auto_json_guide('Log path segments from JSON are joined into a local file read.', 'log.segments[]', 'pages/home.php', 'Segment array reaches file_get_contents.'),
        '/auto/file/export-name' => auto_json_guide('Export filename and body from JSON are written to a web-accessible file.', 'export.filename + export.body', 'auto_export_name.json', 'Export descriptor reaches file_put_contents.'),
        '/auto/ssrf/rss-feed' => auto_json_guide('Feed URL JSON is fetched server-side.', 'feeds[0].url', 'data://text/plain,auto_ssrf_rss_ok', 'RSS feed JSON reaches file_get_contents.'),
        '/auto/ssrf/proxy-chain' => auto_json_guide('A later hop in a JSON proxy chain is fetched server-side.', 'proxy.chain[1].target.href', 'data://text/plain,auto_ssrf_proxy_chain_ok', 'Proxy chain JSON reaches file_get_contents.'),
        '/auto/ssrf/cloud-metadata' => auto_json_guide('Cloud metadata URL JSON is fetched server-side.', 'cloud.metadata.url', 'data://text/plain,auto_ssrf_metadata_ok', 'Cloud metadata JSON reaches file_get_contents.'),
        '/auto/xss/notification-template' => auto_json_guide('Notification template HTML from JSON is interpolated without encoding.', 'notification.template', '<img src=x onerror=alert(1)>', 'Notification template appears in HTML preview.'),
        '/auto/xss/table-cell' => auto_json_guide('Table cell values from JSON are inserted as raw HTML.', 'table.rows[0].cells[1].value', '<svg onload=alert(1)>', 'Table cell JSON appears in HTML preview.'),
        '/auto/xss/email-preview' => auto_json_guide('Email HTML part JSON is rendered in a preview.', 'email.parts.html', '<a href=javascript:alert(1)>', 'Email preview JSON appears in HTML preview.'),
        '/auto/idor/project-role' => auto_json_guide('Project member id JSON is read without checking actor membership.', 'project.members[0].user_id', '3 while actor.user_id is 1', 'Admin project role row is returned.'),
        '/auto/idor/api-key-read' => auto_json_guide('API key owner JSON controls which derived key is returned.', 'secrets.owner.user_id', '3 while actor.user_id is 1', 'Another user API key preview is returned.'),
        '/auto/auth/oauth-callback' => auto_json_guide('OAuth callback claims from JSON are trusted as authenticated identity.', 'oauth.claims.sub', '3', 'Session user becomes the claimed admin user.'),
        '/auto/auth/jwt-none' => auto_json_guide('Unsigned JWT-style JSON claims are trusted when alg is none.', 'jwt.claims.user_id', '3', 'Session JWT identity becomes admin.'),
        '/auto/state/preferences-merge' => auto_json_guide('Deep preference overrides from JSON are merged into trusted session state.', 'preferences.overrides.is_admin', 'true', 'Privilege-like preference flag is stored.'),
        '/auto/state/inventory-adjust' => auto_json_guide('Inventory delta JSON is trusted and written as adjustment state.', 'adjustments[0].delta', '-999', 'Inventory adjustment artifact is written.'),
        '/auto/deserialization/signed-envelope' => auto_json_guide('A signed envelope payload is decoded and unserialized while ignoring the signature.', 'envelope.payload.serialized_b64', 'base64 serialized stdClass', 'Signed envelope JSON reaches unserialize().'),
        '/auto/redirect/deep-link' => auto_json_guide('A deep link href in a JSON link array is used as a Location header.', 'app.links[0].href', 'https://example.org/auto-deep-link', 'JSON link target is emitted as redirect.'),
        '/auto/cors/tenant-origin-list' => auto_json_guide('Tenant origin arrays in JSON are reflected as credentialed CORS policy.', 'tenants[0].allowed_origins[1]', 'https://evil-tenant.example.test', 'Tenant origin JSON is reflected in CORS headers.'),
        '/session/debug' => array(
            'vulnerable_situation' => 'Route discloses session/cookie/header internals and permits insecure cookie writes.',
            'required_variables' => array(
                array('name' => 'set', 'location' => 'GET', 'required' => 'No', 'example' => 'fuzzer_token', 'notes' => 'Cookie name to set with insecure attributes.'),
                array('name' => 'value', 'location' => 'GET', 'required' => 'No', 'example' => 'demo', 'notes' => 'Cookie value to set and reflect.'),
            ),
            'exploit_steps' => array('Request endpoint to inspect full session/cookie map.', 'Set arbitrary cookie values and confirm exposure.'),
            'expected_fuzzer_signal' => array('Sensitive runtime/session metadata exposed in response body.'),
        ),
    );
}

function catalog_entries(): array
{
    return array(
        array('path' => '/', 'method' => 'GET', 'category' => 'navigation', 'difficulty' => 'basic', 'auth_required' => false, 'description' => 'Portal with links by vulnerability category.', 'expected_signal' => 'crawler discovery'),
        array('path' => '/auto/rce/system', 'method' => 'GET', 'category' => 'auto', 'target_category' => 'rce', 'target_api' => '/api/json/rce/system', 'trigger_event' => 'page_load', 'request_body_format' => 'json', 'difficulty' => 'intermediate', 'auth_required' => false, 'description' => 'Crawlable page that auto-posts JSON to the RCE API on load.', 'expected_signal' => 'page-load JSON fetch returns command output'),
        array('path' => '/auto/file/lfi', 'method' => 'GET', 'category' => 'auto', 'target_category' => 'lfi', 'target_api' => '/api/json/file/lfi', 'trigger_event' => 'page_load', 'request_body_format' => 'json', 'difficulty' => 'intermediate', 'auth_required' => false, 'description' => 'Crawlable page that auto-posts JSON path material to the LFI API.', 'expected_signal' => 'page-load JSON fetch returns include/read preview'),
        array('path' => '/auto/sqli/error', 'method' => 'GET', 'category' => 'auto', 'target_category' => 'sqli', 'target_api' => '/api/json/sqli/error', 'trigger_event' => 'page_load', 'request_body_format' => 'json', 'difficulty' => 'intermediate', 'auth_required' => false, 'description' => 'Crawlable page that auto-posts JSON SQLi input to the SQL API.', 'expected_signal' => 'page-load JSON fetch returns SQL error or rows'),
        array('path' => '/auto/ssrf/fetch', 'method' => 'GET', 'category' => 'auto', 'target_category' => 'ssrf', 'target_api' => '/api/json/ssrf/fetch', 'trigger_event' => 'page_load', 'request_body_format' => 'json', 'difficulty' => 'intermediate', 'auth_required' => false, 'description' => 'Crawlable page that auto-posts a JSON URL to the SSRF API.', 'expected_signal' => 'page-load JSON fetch returns server-side fetch preview'),
        array('path' => '/auto/xss/stored-comment', 'method' => 'GET', 'category' => 'auto', 'target_category' => 'xss', 'target_api' => '/api/json/xss/stored-comment', 'trigger_event' => 'page_load', 'request_body_format' => 'json', 'difficulty' => 'intermediate', 'auth_required' => false, 'description' => 'Crawlable page that auto-posts a stored XSS comment through JSON.', 'expected_signal' => 'page-load JSON fetch stores comment metadata'),
        array('path' => '/auto/idor/order', 'method' => 'GET', 'category' => 'auto', 'target_category' => 'idor', 'target_api' => '/api/json/idor/order', 'trigger_event' => 'page_load', 'request_body_format' => 'json', 'difficulty' => 'intermediate', 'auth_required' => false, 'description' => 'Crawlable page that auto-posts a cross-user order lookup through JSON.', 'expected_signal' => 'page-load JSON fetch returns another user order'),
        array('path' => '/auto/state/change-email', 'method' => 'GET', 'category' => 'auto', 'target_category' => 'state_change', 'target_api' => '/api/json/state/change-email', 'trigger_event' => 'page_load', 'request_body_format' => 'json', 'difficulty' => 'intermediate', 'auth_required' => false, 'description' => 'Crawlable page that auto-posts a JSON email state change.', 'expected_signal' => 'page-load JSON fetch updates database state'),
        array('path' => '/auto/session/set-cookie', 'method' => 'GET', 'category' => 'auto', 'target_category' => 'session', 'target_api' => '/api/json/session/set-cookie', 'trigger_event' => 'page_load', 'request_body_format' => 'json', 'difficulty' => 'intermediate', 'auth_required' => false, 'description' => 'Crawlable page that auto-posts JSON cookie material to an insecure cookie sink.', 'expected_signal' => 'page-load JSON fetch returns Set-Cookie header'),
        auto_catalog_entry('/auto/rce/argv-array', 'rce', '/api/json/rce/argv-array', 'array', 'Crawlable page that auto-posts argv-style JSON to an RCE sink.', 'page-load JSON fetch returns argv command output'),
        auto_catalog_entry('/auto/rce/workflow-step', 'rce', '/api/json/rce/workflow-step', 'hard', 'Crawlable page that auto-posts workflow-step JSON to an RCE sink.', 'deep workflow JSON path returns command output'),
        auto_catalog_entry('/auto/sqli/search-filter', 'sqli', '/api/json/sqli/search-filter', 'nested', 'Crawlable page that auto-posts nested search criteria to SQLi.', 'nested JSON search field changes SQL rows'),
        auto_catalog_entry('/auto/sqli/sort-clause', 'sqli', '/api/json/sqli/sort-clause', 'nested', 'Crawlable page that auto-posts sort metadata into ORDER BY SQL.', 'sort JSON reaches SQL query text'),
        auto_catalog_entry('/auto/sqli/batch-lookup', 'sqli', '/api/json/sqli/batch-lookup', 'hard', 'Crawlable page that auto-posts selected batch JSON into SQLi.', 'array-selected JSON id changes SQL rows'),
        auto_catalog_entry('/auto/file/lang-include', 'lfi', '/api/json/file/lang-include', 'nested', 'Crawlable page that auto-posts locale/template JSON into include/read.', 'nested path JSON returns include/read preview'),
        auto_catalog_entry('/auto/file/path-parts', 'lfi', '/api/json/file/path-parts', 'array', 'Crawlable page that auto-posts path-part JSON into file read.', 'array path JSON returns file preview'),
        auto_catalog_entry('/auto/file/write-json', 'file_write', '/api/json/file/write-json', 'easy', 'Crawlable page that auto-posts JSON artifact data into file_put_contents.', 'page-load JSON fetch writes a fixed artifact'),
        auto_catalog_entry('/auto/ssrf/webhook-basic', 'ssrf', '/api/json/ssrf/webhook-basic', 'easy', 'Crawlable page that auto-posts scalar webhook URL to SSRF sink.', 'scalar JSON URL returns fetch preview'),
        auto_catalog_entry('/auto/ssrf/events-callback', 'ssrf', '/api/json/ssrf/events-callback', 'hard', 'Crawlable page that auto-posts deep event callback JSON to SSRF sink.', 'deep callback URL returns fetch preview'),
        auto_catalog_entry('/auto/xss/profile-card', 'xss', '/api/json/xss/profile-card', 'nested', 'Crawlable page that auto-posts profile JSON into HTML template.', 'JSON-controlled HTML appears in response'),
        auto_catalog_entry('/auto/xss/dom-fragment', 'xss', '/api/json/xss/dom-fragment', 'array', 'Crawlable page that auto-posts widget HTML JSON for DOM insertion.', 'array-held HTML fragment appears in response'),
        auto_catalog_entry('/auto/idor/account-balance', 'idor', '/api/json/idor/account-balance', 'nested', 'Crawlable page that auto-posts nested account id JSON into IDOR lookup.', 'response returns another user account balance'),
        auto_catalog_entry('/auto/auth/mass-assignment-role', 'auth', '/api/json/auth/mass-assignment-role', 'hard', 'Crawlable page that auto-posts profile role JSON into mass assignment update.', 'JSON role field changes user authorization state'),
        auto_catalog_entry('/auto/state/transfer-log', 'state_change', '/api/json/state/transfer-log', 'nested', 'Crawlable page that auto-posts transfer JSON into a state-changing insert.', 'page-load JSON fetch creates transfer log row'),
        auto_catalog_entry('/auto/deserialization/php-object', 'deserialization', '/api/json/deserialization/php-object', 'easy', 'Crawlable page that auto-posts serialized PHP object text into unserialize().', 'response reports unserialized object result'),
        auto_catalog_entry('/auto/cors/reflect-origin-json', 'cors', '/api/json/cors/reflect-origin-json', 'nested', 'Crawlable page that auto-posts origin JSON into CORS reflection.', 'response reflects attacker origin with credentials'),
        auto_catalog_entry('/auto/rce/template-eval', 'rce', '/api/json/rce/template-eval', 'nested', 'Crawlable page that auto-posts PHP template JSON into eval().', 'page-load JSON fetch returns eval output'),
        auto_catalog_entry('/auto/rce/env-chain', 'rce', '/api/json/rce/env-chain', 'hard', 'Crawlable page that auto-posts env-style command JSON into shell_exec().', 'metadata-disguised JSON returns command output'),
        auto_catalog_entry('/auto/sqli/graphql-user', 'sqli', '/api/json/sqli/graphql-user', 'nested', 'Crawlable page that auto-posts GraphQL-like JSON variables into SQLi.', 'GraphQL variable JSON changes SQL rows'),
        auto_catalog_entry('/auto/sqli/report-range', 'sqli', '/api/json/sqli/report-range', 'hard', 'Crawlable page that auto-posts report filter JSON into SQLi.', 'report filter JSON changes SQL rows'),
        auto_catalog_entry('/auto/sqli/ids-array', 'sqli', '/api/json/sqli/ids-array', 'array', 'Crawlable page that auto-posts ID array JSON into SQL IN clause.', 'array JSON changes SQL predicate behavior'),
        auto_catalog_entry('/auto/sqli/json-operator', 'sqli', '/api/json/sqli/json-operator', 'hard', 'Crawlable page that auto-posts dynamic predicate JSON into SQLi.', 'operator JSON changes SQL rows'),
        auto_catalog_entry('/auto/file/base64-read', 'lfi', '/api/json/file/base64-read', 'encoded', 'Crawlable page that auto-posts base64 path JSON into file read.', 'encoded JSON path returns file preview'),
        auto_catalog_entry('/auto/file/theme-asset', 'lfi', '/api/json/file/theme-asset', 'nested', 'Crawlable page that auto-posts theme asset JSON into file read.', 'theme JSON path returns file preview'),
        auto_catalog_entry('/auto/file/temp-cleanup', 'file_delete', '/api/json/file/temp-cleanup', 'array', 'Crawlable page that auto-posts cleanup target JSON into unlink().', 'cleanup target JSON deletes fixed marker file'),
        auto_catalog_entry('/auto/ssrf/oembed-url', 'ssrf', '/api/json/ssrf/oembed-url', 'nested', 'Crawlable page that auto-posts oEmbed endpoint JSON to SSRF sink.', 'oEmbed JSON URL returns fetch preview'),
        auto_catalog_entry('/auto/ssrf/openapi-server', 'ssrf', '/api/json/ssrf/openapi-server', 'array', 'Crawlable page that auto-posts OpenAPI server JSON to SSRF sink.', 'OpenAPI server JSON returns fetch preview'),
        auto_catalog_entry('/auto/ssrf/avatar-proxy', 'ssrf', '/api/json/ssrf/avatar-proxy', 'array', 'Crawlable page that auto-posts avatar URL JSON to SSRF sink.', 'array object URL returns fetch preview'),
        auto_catalog_entry('/auto/xss/markdown-preview', 'xss', '/api/json/xss/markdown-preview', 'easy', 'Crawlable page that auto-posts markdown JSON into unsafe HTML preview.', 'markdown JSON appears in HTML preview'),
        auto_catalog_entry('/auto/xss/svg-avatar', 'xss', '/api/json/xss/svg-avatar', 'nested', 'Crawlable page that auto-posts SVG JSON into render preview.', 'SVG JSON appears in response preview'),
        auto_catalog_entry('/auto/xss/json-error-message', 'xss', '/api/json/xss/json-error-message', 'array', 'Crawlable page that auto-posts error message JSON into HTML banner.', 'error-array JSON appears in HTML preview'),
        auto_catalog_entry('/auto/idor/invoice-export', 'idor', '/api/json/idor/invoice-export', 'nested', 'Crawlable page that auto-posts invoice export JSON into IDOR lookup.', 'another user invoice/order is returned'),
        auto_catalog_entry('/auto/idor/team-settings', 'idor', '/api/json/idor/team-settings', 'array', 'Crawlable page that auto-posts team member JSON into IDOR lookup.', 'another user settings row is returned'),
        auto_catalog_entry('/auto/auth/debug-impersonate', 'auth', '/api/json/auth/debug-impersonate', 'hard', 'Crawlable page that auto-posts debug impersonation JSON into session assignment.', 'session user changes to requested account'),
        auto_catalog_entry('/auto/auth/password-reset-token', 'auth', '/api/json/auth/password-reset-token', 'easy', 'Crawlable page that auto-posts reset email JSON into predictable token disclosure.', 'predictable reset token is returned'),
        auto_catalog_entry('/auto/state/feature-flag', 'state_change', '/api/json/state/feature-flag', 'array', 'Crawlable page that auto-posts feature flag JSON into trusted state.', 'feature flag state artifact is written'),
        auto_catalog_entry('/auto/state/cart-price', 'state_change', '/api/json/state/cart-price', 'array', 'Crawlable page that auto-posts cart price JSON into trusted total calculation.', 'client-controlled price becomes server total'),
        auto_catalog_entry('/auto/deserialization/base64-object', 'deserialization', '/api/json/deserialization/base64-object', 'encoded', 'Crawlable page that auto-posts base64 serialized object JSON into unserialize().', 'encoded object reaches deserialization sink'),
        auto_catalog_entry('/auto/redirect/json-next', 'open_redirect', '/api/json/redirect/json-next', 'nested', 'Crawlable page that auto-posts navigation JSON into Location header.', 'JSON-controlled redirect target is emitted'),
        auto_catalog_entry('/auto/cors/preflight-cache', 'cors', '/api/json/cors/preflight-cache', 'array', 'Crawlable page that auto-posts CORS policy JSON into reflected preflight headers.', 'origin, headers, and max-age reflect from JSON'),
        auto_catalog_entry('/auto/rce/header-command', 'rce', '/api/json/rce/header-command', 'nested', 'Crawlable page that auto-posts header-map JSON into system().', 'header-map JSON returns command output'),
        auto_catalog_entry('/auto/rce/task-matrix', 'rce', '/api/json/rce/task-matrix', 'hard', 'Crawlable page that auto-posts matrix-cell JSON into shell_exec().', 'matrix-cell JSON returns command output'),
        auto_catalog_entry('/auto/sqli/join-fragment', 'sqli', '/api/json/sqli/join-fragment', 'hard', 'Crawlable page that auto-posts JOIN fragment JSON into SQLi.', 'JOIN metadata changes SQL row shape'),
        auto_catalog_entry('/auto/sqli/having-metric', 'sqli', '/api/json/sqli/having-metric', 'hard', 'Crawlable page that auto-posts analytics HAVING JSON into SQLi.', 'metric JSON changes grouped query rows'),
        auto_catalog_entry('/auto/sqli/limit-offset', 'sqli', '/api/json/sqli/limit-offset', 'nested', 'Crawlable page that auto-posts pagination JSON into SQL syntax.', 'pagination JSON reaches query text or DB error'),
        auto_catalog_entry('/auto/sqli/json-search-doc', 'sqli', '/api/json/sqli/json-search-doc', 'hard', 'Crawlable page that auto-posts document-filter JSON into SQLi.', 'document filter JSON changes SQL rows'),
        auto_catalog_entry('/auto/file/archive-extract', 'file_write', '/api/json/file/archive-extract', 'array', 'Crawlable page that auto-posts archive-entry JSON into file write.', 'archive path writes fixed artifact'),
        auto_catalog_entry('/auto/file/log-read', 'lfi', '/api/json/file/log-read', 'array', 'Crawlable page that auto-posts log segment JSON into file read.', 'segment array returns file preview'),
        auto_catalog_entry('/auto/file/export-name', 'file_write', '/api/json/file/export-name', 'nested', 'Crawlable page that auto-posts export descriptor JSON into file write.', 'export filename writes fixed artifact'),
        auto_catalog_entry('/auto/ssrf/rss-feed', 'ssrf', '/api/json/ssrf/rss-feed', 'array', 'Crawlable page that auto-posts RSS feed JSON into SSRF sink.', 'feed URL JSON returns fetch preview'),
        auto_catalog_entry('/auto/ssrf/proxy-chain', 'ssrf', '/api/json/ssrf/proxy-chain', 'hard', 'Crawlable page that auto-posts proxy-chain JSON into SSRF sink.', 'later-hop URL JSON returns fetch preview'),
        auto_catalog_entry('/auto/ssrf/cloud-metadata', 'ssrf', '/api/json/ssrf/cloud-metadata', 'nested', 'Crawlable page that auto-posts cloud metadata JSON into SSRF sink.', 'metadata URL JSON returns fetch preview'),
        auto_catalog_entry('/auto/xss/notification-template', 'xss', '/api/json/xss/notification-template', 'nested', 'Crawlable page that auto-posts notification template JSON into HTML.', 'notification template appears in HTML preview'),
        auto_catalog_entry('/auto/xss/table-cell', 'xss', '/api/json/xss/table-cell', 'array', 'Crawlable page that auto-posts table-cell JSON into raw HTML.', 'table cell HTML appears in response'),
        auto_catalog_entry('/auto/xss/email-preview', 'xss', '/api/json/xss/email-preview', 'nested', 'Crawlable page that auto-posts email part JSON into preview HTML.', 'email HTML appears in response'),
        auto_catalog_entry('/auto/idor/project-role', 'idor', '/api/json/idor/project-role', 'array', 'Crawlable page that auto-posts project member JSON into IDOR lookup.', 'admin project role row is returned'),
        auto_catalog_entry('/auto/idor/api-key-read', 'idor', '/api/json/idor/api-key-read', 'hard', 'Crawlable page that auto-posts API key owner JSON into key disclosure.', 'another user API key preview is returned'),
        auto_catalog_entry('/auto/auth/oauth-callback', 'auth', '/api/json/auth/oauth-callback', 'nested', 'Crawlable page that auto-posts OAuth claims JSON into session assignment.', 'session user becomes claimed admin'),
        auto_catalog_entry('/auto/auth/jwt-none', 'auth', '/api/json/auth/jwt-none', 'hard', 'Crawlable page that auto-posts unsigned JWT-style JSON into trusted identity.', 'session JWT identity becomes admin'),
        auto_catalog_entry('/auto/state/preferences-merge', 'state_change', '/api/json/state/preferences-merge', 'hard', 'Crawlable page that auto-posts deep preference JSON into trusted state.', 'privilege-like preference flag is stored'),
        auto_catalog_entry('/auto/state/inventory-adjust', 'state_change', '/api/json/state/inventory-adjust', 'array', 'Crawlable page that auto-posts inventory adjustment JSON into trusted state.', 'inventory adjustment artifact is written'),
        auto_catalog_entry('/auto/deserialization/signed-envelope', 'deserialization', '/api/json/deserialization/signed-envelope', 'encoded', 'Crawlable page that auto-posts signed-envelope JSON into unserialize().', 'signed envelope payload reaches deserialization sink'),
        auto_catalog_entry('/auto/redirect/deep-link', 'open_redirect', '/api/json/redirect/deep-link', 'array', 'Crawlable page that auto-posts deep-link JSON into Location header.', 'deep link target is emitted as redirect'),
        auto_catalog_entry('/auto/cors/tenant-origin-list', 'cors', '/api/json/cors/tenant-origin-list', 'array', 'Crawlable page that auto-posts tenant origin JSON into CORS reflection.', 'tenant origin reflects with credentials'),
        array('path' => '/xss/reflected?input=<script>alert(1)</script>', 'method' => 'GET', 'category' => 'xss', 'difficulty' => 'basic', 'auth_required' => false, 'description' => 'Raw reflected HTML/JS context.', 'expected_signal' => 'script execution in response body'),
        array('path' => '/xss/attr?input=" onmouseover="alert(1)', 'method' => 'GET', 'category' => 'xss', 'difficulty' => 'intermediate', 'auth_required' => false, 'description' => 'Attribute context injection.', 'expected_signal' => 'attribute breakout payload'),
        array('path' => '/xss/js?input=' . rawurlencode("';alert(1);//"), 'method' => 'GET', 'category' => 'xss', 'difficulty' => 'intermediate', 'auth_required' => false, 'description' => 'JavaScript string-context injection.', 'expected_signal' => 'JS syntax break and execution'),
        array('path' => '/xss/stored', 'method' => 'GET/POST', 'category' => 'xss', 'difficulty' => 'intermediate', 'auth_required' => false, 'description' => 'Stored XSS in comment board.', 'expected_signal' => 'persisted payload execution'),
        array('path' => '/xss/filtered?input=<svg/onload=alert(1)>', 'method' => 'GET', 'category' => 'xss', 'difficulty' => 'constrained', 'auth_required' => false, 'description' => 'Naively filtered XSS route.', 'expected_signal' => 'filter bypass'),
        array('path' => '/sqli/error?id=1', 'method' => 'GET', 'category' => 'sqli', 'difficulty' => 'basic', 'auth_required' => false, 'description' => 'Error-based SQL injection route.', 'expected_signal' => 'SQL errors and DB stack hints'),
        array('path' => '/api/json/sqli/error', 'interactive_path' => '/json/sqli/error', 'method' => 'POST JSON', 'category' => 'sqli', 'difficulty' => 'intermediate', 'auth_required' => false, 'description' => 'Error-based SQLi from nested JSON body fields.', 'expected_signal' => 'JSON body SQL error or row differential'),
        array('path' => '/sqli/union?id=1', 'method' => 'GET', 'category' => 'sqli', 'difficulty' => 'basic', 'auth_required' => false, 'description' => 'Union-based SQL injection route.', 'expected_signal' => 'unexpected row expansion'),
        array('path' => '/sqli/blind-bool?id=1', 'method' => 'GET', 'category' => 'sqli', 'difficulty' => 'intermediate', 'auth_required' => false, 'description' => 'Boolean blind SQL injection route.', 'expected_signal' => 'content differential true/false'),
        array('path' => '/sqli/blind-time?id=1', 'method' => 'GET', 'category' => 'sqli', 'difficulty' => 'intermediate', 'auth_required' => false, 'description' => 'Time-based blind SQL injection route.', 'expected_signal' => 'response latency differential'),
        array('path' => '/sqli/constrained?id=alice', 'method' => 'GET', 'category' => 'sqli', 'difficulty' => 'constrained', 'auth_required' => false, 'description' => 'Naively filtered SQLi requiring finessing.', 'expected_signal' => 'blacklist bypass'),
        array('path' => '/sqli/login', 'method' => 'GET/POST', 'category' => 'sqli', 'difficulty' => 'basic', 'auth_required' => false, 'description' => 'Authentication bypass SQLi form.', 'expected_signal' => 'login bypass'),
        array('path' => '/auth/login', 'method' => 'GET/POST', 'category' => 'auth', 'difficulty' => 'basic', 'auth_required' => false, 'description' => 'Session login for CSRF/IDOR workflows.', 'expected_signal' => 'session cookie issuance'),
        array('path' => '/auth/logout', 'method' => 'GET', 'category' => 'auth', 'difficulty' => 'basic', 'auth_required' => true, 'description' => 'Session logout endpoint.', 'expected_signal' => 'session invalidation'),
        array('path' => '/csrf/change-email', 'method' => 'GET/POST', 'category' => 'csrf', 'difficulty' => 'basic', 'auth_required' => true, 'description' => 'State change with no CSRF token.', 'expected_signal' => 'cross-site state change'),
        array('path' => '/csrf/transfer', 'method' => 'GET/POST', 'category' => 'csrf', 'difficulty' => 'intermediate', 'auth_required' => true, 'description' => 'Money transfer with no CSRF token.', 'expected_signal' => 'unauthorized transfer by forged request'),
        array('path' => '/csrf/weak-token', 'method' => 'GET/POST', 'category' => 'csrf', 'difficulty' => 'constrained', 'auth_required' => true, 'description' => 'Predictable weak CSRF token validation.', 'expected_signal' => 'token prediction/bypass'),
        array('path' => '/rce/system?cmd=id', 'method' => 'GET', 'category' => 'rce', 'difficulty' => 'basic', 'auth_required' => false, 'description' => 'Direct system command execution.', 'expected_signal' => 'command output'),
        array('path' => '/rce/filtered?cmd=whoami', 'method' => 'GET', 'category' => 'rce', 'difficulty' => 'constrained', 'auth_required' => false, 'description' => 'Weak command filter with bypass surface.', 'expected_signal' => 'filtered payload bypass'),
        array('path' => '/rce/eval?code=' . rawurlencode('echo phpversion();'), 'method' => 'GET', 'category' => 'rce', 'difficulty' => 'basic', 'auth_required' => false, 'description' => 'Unsafe eval of user-supplied code.', 'expected_signal' => 'code execution output'),
        array('path' => '/api/json/rce/system', 'interactive_path' => '/json/rce/system', 'method' => 'POST JSON', 'category' => 'rce', 'difficulty' => 'intermediate', 'auth_required' => false, 'description' => 'Direct system command execution from nested JSON command field.', 'expected_signal' => 'JSON body command output'),
        array('path' => '/ssrf/fetch?url=' . rawurlencode('http://127.0.0.1:9/'), 'method' => 'GET', 'category' => 'ssrf', 'difficulty' => 'basic', 'auth_required' => false, 'description' => 'Raw URL fetch SSRF route.', 'expected_signal' => 'server-side fetch of attacker target'),
        array('path' => '/ssrf/weak-filter?url=' . rawurlencode('http://127.1:9/'), 'method' => 'GET', 'category' => 'ssrf', 'difficulty' => 'constrained', 'auth_required' => false, 'description' => 'Weak localhost filter SSRF route.', 'expected_signal' => 'filter bypass to local targets'),
        array('path' => '/ssrf/redirect?url=' . rawurlencode('http://127.0.0.1:9/redirect?next=http://127.0.0.1:9/session/debug'), 'method' => 'GET', 'category' => 'ssrf', 'difficulty' => 'intermediate', 'auth_required' => false, 'description' => 'Redirect-follow SSRF route.', 'expected_signal' => 'redirect chain to internal resource'),
        array('path' => '/file/lfi?page=home', 'method' => 'GET', 'category' => 'lfi', 'difficulty' => 'basic', 'auth_required' => false, 'description' => 'File include/read with traversal surface.', 'expected_signal' => 'local file disclosure'),
        array('path' => '/file/lfi-constrained?page=home', 'method' => 'GET', 'category' => 'lfi', 'difficulty' => 'constrained', 'auth_required' => false, 'description' => 'Naive traversal sanitization path.', 'expected_signal' => 'sanitization bypass'),
        array('path' => '/file/rfi?url=' . rawurlencode('php://filter/resource=/etc/hosts'), 'method' => 'GET', 'category' => 'rfi', 'difficulty' => 'basic', 'auth_required' => false, 'description' => 'Remote file include route (allow_url_include required).', 'expected_signal' => 'remote include execution'),
        array('path' => '/api/json/file/lfi', 'interactive_path' => '/json/file/lfi', 'method' => 'POST JSON', 'category' => 'lfi', 'difficulty' => 'intermediate', 'auth_required' => false, 'description' => 'Local file include/read from nested JSON path fields.', 'expected_signal' => 'JSON body local file disclosure'),
        array('path' => '/idor/order?id=1', 'method' => 'GET', 'category' => 'idor', 'difficulty' => 'basic', 'auth_required' => true, 'description' => 'Object fetch without ownership check by default.', 'expected_signal' => 'cross-tenant record access'),
        array('path' => '/upload/shell', 'method' => 'GET/POST', 'category' => 'upload', 'difficulty' => 'intermediate', 'auth_required' => false, 'description' => 'Weak upload validation enabling executable files.', 'expected_signal' => 'web shell upload/execution'),
        array('path' => '/redirect?next=https://example.org', 'method' => 'GET', 'category' => 'open_redirect', 'difficulty' => 'basic', 'auth_required' => false, 'description' => 'Open redirect without validation.', 'expected_signal' => 'external redirect control'),
        array('path' => '/session/debug', 'method' => 'GET', 'category' => 'session', 'difficulty' => 'basic', 'auth_required' => false, 'description' => 'Insecure session/cookie visibility endpoint.', 'expected_signal' => 'session metadata exposure'),
    );
}
