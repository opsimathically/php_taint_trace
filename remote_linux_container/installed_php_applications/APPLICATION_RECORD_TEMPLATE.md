# Application Record Template

Use this schema when adding entries to `inventory.json`.

```json
{
  "app_id": "wordpress-main",
  "name": "WordPress",
  "slug": "wordpress",
  "status": "installed",
  "version": "6.9.4",
  "installed_at_utc": "2026-04-26T00:00:00Z",
  "installed_by": "operator",
  "remote_host_label": "lab.example.invalid",
  "remote_root_path": "/opt/php_taint_trace_vuln_lab/apps/wordpress",
  "web_root_path": "/opt/php_taint_trace_vuln_lab/apps/wordpress/public",
  "base_urls": [
    "http://192.0.2.10:19XXX/"
  ],
  "deployment": {
    "endpoint": "192.0.2.10",
    "port": 19130,
    "nginx_site_conf": "/etc/nginx/sites-available/wordpress-ptt.conf",
    "php_fpm_pool_conf": "/etc/php/8.3/fpm/pool.d/wordpress-ptt.conf",
    "php_fpm_socket": "/run/php/php8.3-fpm-wordpress.sock"
  },
  "runtime": {
    "php_version": "8.3.x",
    "sapi": "fpm-fcgi|cli-server|swoole|other",
    "database": "mysql|mariadb|sqlite|postgresql",
    "database_version": "8.0.x"
  },
  "source": {
    "download_url": "https://example.org/releases/app-x.y.z.tar.gz",
    "checksum": "sha256:...",
    "release_date": "2026-03-11"
  },
  "php_taint_trace_integration": {
    "enabled": true,
    "mode": "auto_prepend|native_extension|both",
    "config_file": "/etc/php_taint_trace/runtime.json",
    "verifier_runtime_dir": "/opt/php_audit_apps/_runtime/wordpress/verifier",
    "verifier_replay_target": "local",
    "verifier_local_base_url": "http://127.0.0.1:19130",
    "notes": "Any app-specific integration notes."
  },
  "credentials": {
    "db_name": "wp_wordpress",
    "db_user": "wp_wordpress_user",
    "db_password": "example",
    "wp_admin_user": "wp_admin_wordpress",
    "wp_admin_password": "example",
    "wp_admin_email": "audit+wordpress@local.invalid"
  },
  "plugin_inventory": {
    "official": {
      "requested": [],
      "installed": [],
      "skipped": []
    },
    "third_party": {
      "requested": [],
      "installed": [],
      "skipped": []
    }
  },
  "snapshot_state": {
    "last_created_at_utc": "2026-04-26T00:00:00Z",
    "last_restored_at_utc": null,
    "db_snapshot_path": "/opt/php_audit_apps/_runtime/wordpress/snapshots/latest/db.sql",
    "content_snapshot_path": "/opt/php_audit_apps/_runtime/wordpress/snapshots/latest/wp-content.tar.gz"
  },
  "audit_scope": {
    "enabled_endpoints": [
      "/",
      "/login"
    ],
    "known_auth_paths": [
      "/wp-login.php"
    ],
    "notes": "Expected high-value attack surface."
  },
  "change_history": [
    {
      "timestamp_utc": "2026-04-26T00:00:00Z",
      "action": "install",
      "summary": "Initial install and baseline integration."
    }
  ]
}
```

`status` values:

- `planned`
- `installed`
- `updated`
- `removed`
- `deprecated`
