# PHP Taint Trace

PHP runtime taint instrumentation and replay-based vulnerability verification, with
a native `xmark` extension, a TypeScript DBGp SDK and a web visualizer for analyst
triage. Detection covers command execution, SQL injection, SSRF, file operations,
XSS, IDOR and XXE through runtime hooks, candidate extraction and verification
oracles. A finding is evidence for review, not a guarantee of exploitability.

## Components

- `src/`: PHP instrumentation, detector slices, reporting, durable verification
  queues, replay policies, confidence scoring and suppression.
- `ext/xmark/`: PHP 8 native taint and opcode/function-hook support.
- `subprojects/nodejs_php_dbgp_client_sdk/`: DBGp listener, inspector, CLI,
  transcript redaction, candidate bridge, replay comparison and stability gates.
- `subprojects/vulnerability_visualizer_ui_daemon/`: Fastify issue projection,
  WebSocket updates, SQLite issue storage and persistent manual triage.
- `human_documentation/high_level_overview/`: architecture and artifact flows.
- `scripts/`: local validation and explicitly invoked lab/operator tools.

## Local development

Use PHP 8.3 or newer with the extensions required by the locked PHPUnit toolchain,
Composer, and Node.js 22 or newer for the two TypeScript components.

```sh
composer install --no-scripts --no-plugins
composer test
composer lint
```

Build the optional native extension locally with `bash scripts/build_xmark_extension.sh`.
The command without `--install` writes only local build output; loading the extension
is a separate PHP configuration choice. The native smoke tests skip when it is absent.

In each Node component directory:

```sh
npm ci --ignore-scripts
npm run typecheck
npm test
npm run build
```

The visualizer requires the locked `better-sqlite3` native binding to be built for
the selected Node ABI. Review its local compilation step before enabling dependency
install hooks. The SDK usage and wire contracts are in its `docs/` directory.

## Configuration and runtime data

Use an external operator configuration and external absolute runtime paths. PHP
loads `PHP_TAINT_TRACE_CONFIG_FILE` (default `/etc/php_taint_trace/runtime.json`);
explicit environment settings take precedence. Runtime examples are in `config/`.
Set `PHP_TAINT_TRACE_VERIFIER_RUNTIME_DIR` and `PHP_TAINT_TRACE_FINDINGS_FILE` to
appropriate external locations before processing real data. Existing relative
defaults are intended for disposable local work; run them from an external working
directory. Never retain live findings, captures, queues, exports or credentials in
the source directory. The webhook example describes a reporting direction; verify
backend support in the current PHP implementation before selecting it.

The visualizer accepts `--config` or `VUI_CONFIG`; set its ingestion, triage,
database and analysis-control paths explicitly outside the source directory. It
has no application authentication boundary and is intended for a trusted local lab.

Remote scripts accept explicit `--config`/`--host-label` options. Their defaults
also accept `PHP_TAINT_TRACE_TEST_CONFIG` and `PHP_TAINT_TRACE_TEST_HOST_LABEL`.
The synthetic host schema is in `config/testing-container.example.json`.
Installed-app inventory and generated state records use
`PHP_TAINT_TRACE_INVENTORY_PATH` and `PHP_TAINT_TRACE_INVENTORY_ROOT`, falling back
to the user's XDG state directory. Public package allowlists remain source assets.
Choose an approved restricted external location for real operator state. No lab
state, credentials or prior deployment is included or restored by this source tree.

Remote deployment, bootstrap, installer, recovery and integration commands can
modify hosts and application data. Invoke them only against an explicitly authorized
test environment. The bundled vulnerable lab applications and synthetic credentials
are fixtures for isolated security testing.

## Verification and licenses

The default PHP suite covers unit and parity contracts; it also exercises owned
script fixtures and native smoke when built. Node tests include synthetic local
socket/CLI cases. These checks do not establish real lab, browser, provider or
deployment readiness. Inherited failures and platform limitations require review.

User-owned rewrite code is MIT licensed. The 89 upstream PRVD test fixtures retained
for parity discovery remain BSD-3-Clause under `PRVD_OLD/LICENSE`; they are not part
of the default PHPUnit execution paths. See `THIRD_PARTY_NOTICES.md`.
