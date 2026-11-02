# Project Drift Controls

## Goal Lock

The active architecture goal is:

1. `php_taint_trace` detects candidates/jobs from runtime taint signals.
2. `php_taint_trace` verification worker + sink oracles perform replay confirmation/scoring and emit decision artifacts/events.
3. `vulnerability_visualizer_ui_daemon` centralizes issue visualization and manual triage.

## v1 Boundaries

- No auth hardening (trusted internal networks only).
- No distributed SQL backend requirement.
- No auto-remediation workflow.
- Focus is security verification signal quality and analyst workflow clarity.

## Integration Contracts That Must Not Drift

- `php_taint_trace` output ingestion: `jobs.jsonl` (+ optional candidates envelope).
- Worker artifact contract: `jobs.jsonl`, `results.jsonl`, `dead_letters.jsonl`, `claims.jsonl`, `decisions.jsonl`.
- UI daemon API contract: `/api/v1/issues`, `/api/v1/issues/:id`, `/api/v1/issues/:id/triage`, `/api/v1/stream/ws`, `/api/v1/sources`.
- Triage persistence: local JSON state + append-only JSONL event history.

## Operational Controls

- Remote daemon deployment and smoke validation scripts:
  - `scripts/provision_remote_node22.sh`
  - `scripts/deploy_remote_daemons.sh`
  - `scripts/run_remote_daemon_smoke.sh`
  - `scripts/run_remote_daemon_full_stack_e2e.sh`
    - Enforces required decision categories by default (`rce,ssrf,sqli,file,xss,idor,xxe`), with explicit override via `--required-categories`.
- Local daemon/sdk quality gate script:
  - `scripts/run_daemon_subproject_checks.sh`
- Runtime baseline contract:
  - Daemon projects target Node `>=22` for full support.
  - `deploy_remote_daemons.sh` enforces Node 22 provisioning by default (`--no-provision-node22` is explicit opt-out).
- Local quality commands are available; hosted CI is not configured.
- UI source contract:
  - UI ingests worker artifacts directly from filesystem paths configured under `fileSources`.
  - `PATCH /api/v1/sources` only toggles file ingestion (`fileSourceEnabled`).

## Anti-Drift Implementation Rule

Any new feature should satisfy at least one:

1. Improves verification accuracy/evidence quality.
2. Improves verifier-to-UI integration reliability/observability.
3. Improves analyst triage clarity or reproducibility.

If a proposed feature does not satisfy one of these, it is out of scope for this architecture track.
