# custom_vuln_lab

`custom_vuln_lab` is an intentionally vulnerable PHP application designed for remote fuzzer capability testing.

Warning: this project is deliberately insecure and must only run in an isolated authorized test environment.

## App Goals

- Broad vulnerability coverage in one crawlable portal.
- Route inventory available at `/catalog` and `/catalog.json`.
- Deterministic seeded data for repeatable fuzzing.

## Defaults

- Slug: `custom_vuln_lab`
- Port: `19162`
- URL: `http://192.0.2.10:19162/`
- DB name: `custom_vuln_lab`
- DB user: `custom_vuln_lab_user`

## Auth Seed Credentials

- `alice / synthetic-lab-alice-only`
- `bob / synthetic-lab-bob-only`
- `admin / synthetic-lab-admin-only`

## Routes

See [`VULNERABILITY_MATRIX.md`](./VULNERABILITY_MATRIX.md) for full route details and sample payload shape.

JSON body targets are available for API scanner testing:

- `POST /api/json/rce/system`
- `POST /api/json/file/lfi`
- `POST /api/json/sqli/error`

All JSON targets require `Content-Type: application/json` and return machine-readable JSON responses.
Browser playgrounds for manual testing are available at:

- `GET /json/rce/system`
- `GET /json/file/lfi`
- `GET /json/sqli/error`

Auto-activated crawler pages are available for JavaScript-aware discovery testing. Each page is a normal `GET` route that documents the target API, fires one JSON `POST` on page load, and displays the response inline:

- `GET /auto/rce/system` -> `POST /api/json/rce/system`
- `GET /auto/file/lfi` -> `POST /api/json/file/lfi`
- `GET /auto/sqli/error` -> `POST /api/json/sqli/error`
- `GET /auto/ssrf/fetch` -> `POST /api/json/ssrf/fetch`
- `GET /auto/xss/stored-comment` -> `POST /api/json/xss/stored-comment`
- `GET /auto/idor/order` -> `POST /api/json/idor/order`
- `GET /auto/state/change-email` -> `POST /api/json/state/change-email`
- `GET /auto/session/set-cookie` -> `POST /api/json/session/set-cookie`
- `GET /auto/rce/argv-array` -> `POST /api/json/rce/argv-array`
- `GET /auto/rce/workflow-step` -> `POST /api/json/rce/workflow-step`
- `GET /auto/sqli/search-filter` -> `POST /api/json/sqli/search-filter`
- `GET /auto/sqli/sort-clause` -> `POST /api/json/sqli/sort-clause`
- `GET /auto/sqli/batch-lookup` -> `POST /api/json/sqli/batch-lookup`
- `GET /auto/file/lang-include` -> `POST /api/json/file/lang-include`
- `GET /auto/file/path-parts` -> `POST /api/json/file/path-parts`
- `GET /auto/file/write-json` -> `POST /api/json/file/write-json`
- `GET /auto/ssrf/webhook-basic` -> `POST /api/json/ssrf/webhook-basic`
- `GET /auto/ssrf/events-callback` -> `POST /api/json/ssrf/events-callback`
- `GET /auto/xss/profile-card` -> `POST /api/json/xss/profile-card`
- `GET /auto/xss/dom-fragment` -> `POST /api/json/xss/dom-fragment`
- `GET /auto/idor/account-balance` -> `POST /api/json/idor/account-balance`
- `GET /auto/auth/mass-assignment-role` -> `POST /api/json/auth/mass-assignment-role`
- `GET /auto/state/transfer-log` -> `POST /api/json/state/transfer-log`
- `GET /auto/deserialization/php-object` -> `POST /api/json/deserialization/php-object`
- `GET /auto/cors/reflect-origin-json` -> `POST /api/json/cors/reflect-origin-json`
- `GET /auto/rce/template-eval` -> `POST /api/json/rce/template-eval`
- `GET /auto/rce/env-chain` -> `POST /api/json/rce/env-chain`
- `GET /auto/sqli/graphql-user` -> `POST /api/json/sqli/graphql-user`
- `GET /auto/sqli/report-range` -> `POST /api/json/sqli/report-range`
- `GET /auto/sqli/ids-array` -> `POST /api/json/sqli/ids-array`
- `GET /auto/sqli/json-operator` -> `POST /api/json/sqli/json-operator`
- `GET /auto/file/base64-read` -> `POST /api/json/file/base64-read`
- `GET /auto/file/theme-asset` -> `POST /api/json/file/theme-asset`
- `GET /auto/file/temp-cleanup` -> `POST /api/json/file/temp-cleanup`
- `GET /auto/ssrf/oembed-url` -> `POST /api/json/ssrf/oembed-url`
- `GET /auto/ssrf/openapi-server` -> `POST /api/json/ssrf/openapi-server`
- `GET /auto/ssrf/avatar-proxy` -> `POST /api/json/ssrf/avatar-proxy`
- `GET /auto/xss/markdown-preview` -> `POST /api/json/xss/markdown-preview`
- `GET /auto/xss/svg-avatar` -> `POST /api/json/xss/svg-avatar`
- `GET /auto/xss/json-error-message` -> `POST /api/json/xss/json-error-message`
- `GET /auto/idor/invoice-export` -> `POST /api/json/idor/invoice-export`
- `GET /auto/idor/team-settings` -> `POST /api/json/idor/team-settings`
- `GET /auto/auth/debug-impersonate` -> `POST /api/json/auth/debug-impersonate`
- `GET /auto/auth/password-reset-token` -> `POST /api/json/auth/password-reset-token`
- `GET /auto/state/feature-flag` -> `POST /api/json/state/feature-flag`
- `GET /auto/state/cart-price` -> `POST /api/json/state/cart-price`
- `GET /auto/deserialization/base64-object` -> `POST /api/json/deserialization/base64-object`
- `GET /auto/redirect/json-next` -> `POST /api/json/redirect/json-next`
- `GET /auto/cors/preflight-cache` -> `POST /api/json/cors/preflight-cache`
- `GET /auto/rce/header-command` -> `POST /api/json/rce/header-command`
- `GET /auto/rce/task-matrix` -> `POST /api/json/rce/task-matrix`
- `GET /auto/sqli/join-fragment` -> `POST /api/json/sqli/join-fragment`
- `GET /auto/sqli/having-metric` -> `POST /api/json/sqli/having-metric`
- `GET /auto/sqli/limit-offset` -> `POST /api/json/sqli/limit-offset`
- `GET /auto/sqli/json-search-doc` -> `POST /api/json/sqli/json-search-doc`
- `GET /auto/file/archive-extract` -> `POST /api/json/file/archive-extract`
- `GET /auto/file/log-read` -> `POST /api/json/file/log-read`
- `GET /auto/file/export-name` -> `POST /api/json/file/export-name`
- `GET /auto/ssrf/rss-feed` -> `POST /api/json/ssrf/rss-feed`
- `GET /auto/ssrf/proxy-chain` -> `POST /api/json/ssrf/proxy-chain`
- `GET /auto/ssrf/cloud-metadata` -> `POST /api/json/ssrf/cloud-metadata`
- `GET /auto/xss/notification-template` -> `POST /api/json/xss/notification-template`
- `GET /auto/xss/table-cell` -> `POST /api/json/xss/table-cell`
- `GET /auto/xss/email-preview` -> `POST /api/json/xss/email-preview`
- `GET /auto/idor/project-role` -> `POST /api/json/idor/project-role`
- `GET /auto/idor/api-key-read` -> `POST /api/json/idor/api-key-read`
- `GET /auto/auth/oauth-callback` -> `POST /api/json/auth/oauth-callback`
- `GET /auto/auth/jwt-none` -> `POST /api/json/auth/jwt-none`
- `GET /auto/state/preferences-merge` -> `POST /api/json/state/preferences-merge`
- `GET /auto/state/inventory-adjust` -> `POST /api/json/state/inventory-adjust`
- `GET /auto/deserialization/signed-envelope` -> `POST /api/json/deserialization/signed-envelope`
- `GET /auto/redirect/deep-link` -> `POST /api/json/redirect/deep-link`
- `GET /auto/cors/tenant-origin-list` -> `POST /api/json/cors/tenant-origin-list`

## Remote Management

Use:

- `scripts/remote_custom_vuln_lab_app_manage.sh install`
- `scripts/remote_custom_vuln_lab_app_manage.sh update`
- `scripts/remote_custom_vuln_lab_app_manage.sh reset`
- `scripts/remote_custom_vuln_lab_app_manage.sh status`
- `scripts/remote_custom_vuln_lab_app_manage.sh remove`
- `scripts/remote_custom_vuln_lab_app_manage.sh register-inventory`

## Notes

- RFI route expects `allow_url_include=1` for this app runtime.
- Upload route intentionally allows executable extensions.
- SQLi endpoints intentionally use unsafe query concatenation.
