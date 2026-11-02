<?php
declare(strict_types=1);

$inventoryPath = dirname(__DIR__) . '/data/inventory.json';

function h(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function request_host_without_port(): string
{
    $host = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? '127.0.0.1';
    $host = trim($host);

    if (str_starts_with($host, '[')) {
        $end = strpos($host, ']');
        if ($end !== false) {
            return substr($host, 1, $end - 1);
        }
    }

    if (substr_count($host, ':') === 1) {
        return explode(':', $host, 2)[0];
    }

    return $host;
}

function request_scheme(): string
{
    $forwarded = strtolower((string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? ''));
    if ($forwarded === 'https') {
        return 'https';
    }

    return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
}

function app_port(array $app): ?int
{
    $port = $app['deployment']['port'] ?? $app['port'] ?? null;
    if (is_int($port)) {
        return $port;
    }
    if (is_string($port) && ctype_digit($port)) {
        return (int)$port;
    }
    return null;
}

function app_status(array $app): string
{
    $status = $app['status'] ?? 'tracked';
    return is_string($status) && $status !== '' ? $status : 'tracked';
}

$inventory = [];
$inventoryError = null;
if (is_file($inventoryPath)) {
    $decoded = json_decode((string)file_get_contents($inventoryPath), true);
    if (is_array($decoded)) {
        $inventory = $decoded;
    } else {
        $inventoryError = 'Inventory JSON could not be parsed.';
    }
} else {
    $inventoryError = 'Inventory JSON was not found.';
}

$apps = [];
foreach (($inventory['applications'] ?? []) as $app) {
    if (!is_array($app)) {
        continue;
    }
    $port = app_port($app);
    if ($port === null) {
        continue;
    }
    $apps[] = $app;
}

usort($apps, static function (array $a, array $b): int {
    return [app_port($a) ?? 0, (string)($a['slug'] ?? '')] <=> [app_port($b) ?? 0, (string)($b['slug'] ?? '')];
});

$host = request_host_without_port();
$scheme = request_scheme();
$generatedAt = gmdate('Y-m-d\TH:i:s\Z');
$inventoryUpdated = is_string($inventory['updated_at_utc'] ?? null) ? $inventory['updated_at_utc'] : 'unknown';
$visualizerUrl = sprintf('%s://%s:19120/', $scheme, $host);
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PHP Audit Apps Portal</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #071013;
      --panel: rgba(12, 31, 36, 0.86);
      --panel-strong: #102a30;
      --line: rgba(143, 218, 222, 0.20);
      --text: #e8fbfc;
      --muted: #89aeb4;
      --accent: #33d6c0;
      --accent-2: #f2b84b;
      --bad: #ff6b6b;
      --shadow: 0 24px 80px rgba(0, 0, 0, 0.34);
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      min-height: 100vh;
      background:
        radial-gradient(circle at 18% 10%, rgba(51, 214, 192, 0.18), transparent 34rem),
        radial-gradient(circle at 88% 12%, rgba(242, 184, 75, 0.16), transparent 28rem),
        linear-gradient(135deg, #071013 0%, #0b171d 42%, #071013 100%);
      color: var(--text);
      font: 16px/1.5 "Aptos", "Segoe UI", sans-serif;
    }

    a { color: inherit; }

    .wrap {
      width: min(1220px, calc(100% - 36px));
      margin: 0 auto;
      padding: 42px 0 54px;
    }

    .hero {
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 28px;
      align-items: end;
      margin-bottom: 26px;
    }

    h1 {
      margin: 0;
      font-size: clamp(2.2rem, 5vw, 5.6rem);
      letter-spacing: -0.07em;
      line-height: 0.9;
    }

    .subtitle {
      max-width: 760px;
      margin: 18px 0 0;
      color: var(--muted);
      font-size: 1.02rem;
    }

    .meta {
      min-width: 270px;
      padding: 16px;
      border: 1px solid var(--line);
      border-radius: 18px;
      background: rgba(7, 16, 19, 0.68);
      box-shadow: var(--shadow);
    }

    .meta div {
      display: flex;
      justify-content: space-between;
      gap: 20px;
      padding: 4px 0;
      color: var(--muted);
      font-size: 0.92rem;
    }

    .meta strong { color: var(--text); font-weight: 700; }

    .toolbar {
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 14px;
      margin: 18px 0 22px;
    }

    input[type="search"] {
      width: 100%;
      padding: 14px 16px;
      border: 1px solid var(--line);
      border-radius: 14px;
      outline: none;
      background: rgba(4, 12, 14, 0.74);
      color: var(--text);
      font: inherit;
    }

    input[type="search"]:focus {
      border-color: rgba(51, 214, 192, 0.70);
      box-shadow: 0 0 0 4px rgba(51, 214, 192, 0.10);
    }

    .utility {
      display: inline-flex;
      align-items: center;
      gap: 10px;
      padding: 0 16px;
      border-radius: 14px;
      background: var(--accent);
      color: #041114;
      text-decoration: none;
      font-weight: 800;
      white-space: nowrap;
    }

    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
      gap: 14px;
    }

    .card {
      position: relative;
      display: flex;
      min-height: 178px;
      flex-direction: column;
      justify-content: space-between;
      gap: 16px;
      padding: 18px;
      border: 1px solid var(--line);
      border-radius: 20px;
      background: linear-gradient(160deg, rgba(16, 42, 48, 0.92), rgba(8, 20, 24, 0.86));
      box-shadow: var(--shadow);
      overflow: hidden;
    }

    .card:before {
      content: "";
      position: absolute;
      inset: 0 0 auto;
      height: 4px;
      background: linear-gradient(90deg, var(--accent), var(--accent-2));
      opacity: 0.85;
    }

    .name {
      margin: 0 0 4px;
      font-size: 1.25rem;
      letter-spacing: -0.02em;
    }

    .slug {
      color: var(--muted);
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 0.86rem;
    }

    .badges {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 12px;
    }

    .badge {
      display: inline-flex;
      align-items: center;
      min-height: 25px;
      padding: 2px 9px;
      border: 1px solid rgba(143, 218, 222, 0.22);
      border-radius: 999px;
      color: var(--muted);
      background: rgba(4, 12, 14, 0.45);
      font-size: 0.82rem;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    }

    .open {
      display: inline-flex;
      justify-content: center;
      align-items: center;
      width: 100%;
      padding: 11px 14px;
      border-radius: 12px;
      background: rgba(51, 214, 192, 0.12);
      border: 1px solid rgba(51, 214, 192, 0.34);
      color: var(--text);
      text-decoration: none;
      font-weight: 800;
    }

    .open:hover, .utility:hover {
      filter: brightness(1.08);
    }

    .url {
      display: block;
      margin-top: 8px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      color: var(--muted);
      font-size: 0.78rem;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    }

    .error {
      padding: 14px 16px;
      border: 1px solid rgba(255, 107, 107, 0.42);
      border-radius: 14px;
      margin-bottom: 18px;
      background: rgba(255, 107, 107, 0.10);
      color: #ffdada;
    }

    .hidden { display: none; }

    @media (max-width: 760px) {
      .hero, .toolbar { grid-template-columns: 1fr; }
      .meta { min-width: 0; }
      .utility { min-height: 48px; justify-content: center; }
    }
  </style>
</head>
<body>
  <main class="wrap">
    <section class="hero">
      <div>
        <h1>PHP Audit Apps</h1>
        <p class="subtitle">
          Live launcher for the PHP audit container. Links are generated from the hostname you used to open this portal, so DHCP changes do not require rewriting this page.
        </p>
      </div>
      <aside class="meta" aria-label="Portal metadata">
        <div><span>Detected host</span><strong id="detected-host"><?= h($host) ?></strong></div>
        <div><span>Tracked apps</span><strong id="tracked-count"><?= count($apps) ?></strong></div>
        <div><span>Inventory updated</span><strong><?= h($inventoryUpdated) ?></strong></div>
        <div><span>Rendered</span><strong><?= h($generatedAt) ?></strong></div>
      </aside>
    </section>

    <?php if ($inventoryError !== null): ?>
      <div class="error"><?= h($inventoryError) ?></div>
    <?php endif; ?>

    <section class="toolbar">
      <input id="filter" type="search" placeholder="Filter by name, slug, port, or runtime..." autocomplete="off">
      <a class="utility dynamic-link" data-port="19120" href="<?= h($visualizerUrl) ?>">Open Visualizer</a>
    </section>

    <section id="app-grid" class="grid" aria-live="polite">
      <?php foreach ($apps as $app):
          $port = app_port($app);
          if ($port === null) {
              continue;
          }
          $name = is_string($app['name'] ?? null) ? $app['name'] : (string)($app['slug'] ?? 'Unnamed app');
          $slug = is_string($app['slug'] ?? null) ? $app['slug'] : 'unknown';
          $appId = is_string($app['app_id'] ?? null) ? $app['app_id'] : '';
          $runtime = $app['runtime'] ?? [];
          $database = is_array($runtime) && is_string($runtime['database'] ?? null) ? $runtime['database'] : '';
          $status = app_status($app);
          $url = sprintf('%s://%s:%d/', $scheme, $host, $port);
          $search = strtolower(trim($name . ' ' . $slug . ' ' . $appId . ' ' . $port . ' ' . $database . ' ' . $status));
      ?>
        <article class="card" data-search="<?= h($search) ?>">
          <div>
            <h2 class="name"><?= h($name) ?></h2>
            <div class="slug"><?= h($slug) ?><?= $appId !== '' ? ' / ' . h($appId) : '' ?></div>
            <div class="badges">
              <span class="badge">port <?= h((string)$port) ?></span>
              <span class="badge"><?= h($status) ?></span>
              <?php if ($database !== ''): ?><span class="badge"><?= h($database) ?></span><?php endif; ?>
            </div>
          </div>
          <div>
            <a class="open dynamic-link" data-port="<?= h((string)$port) ?>" href="<?= h($url) ?>">Open <?= h($name) ?></a>
            <span class="url dynamic-url"><?= h($url) ?></span>
          </div>
        </article>
      <?php endforeach; ?>
    </section>
  </main>

  <script>
    const currentHost = window.location.hostname || <?= json_encode($host) ?>;
    const currentProtocol = window.location.protocol || <?= json_encode($scheme . ':') ?>;
    document.getElementById('detected-host').textContent = currentHost;

    document.querySelectorAll('.dynamic-link').forEach((link) => {
      const port = link.dataset.port;
      if (!port) return;
      link.href = `${currentProtocol}//${currentHost}:${port}/`;
      const urlLabel = link.parentElement?.querySelector('.dynamic-url');
      if (urlLabel) {
        urlLabel.textContent = link.href;
      }
    });

    const filter = document.getElementById('filter');
    const cards = [...document.querySelectorAll('.card')];
    const count = document.getElementById('tracked-count');
    filter.addEventListener('input', () => {
      const query = filter.value.trim().toLowerCase();
      let visible = 0;
      cards.forEach((card) => {
        const matched = !query || card.dataset.search.includes(query);
        card.classList.toggle('hidden', !matched);
        if (matched) visible++;
      });
      count.textContent = String(visible);
    });
  </script>
</body>
</html>
