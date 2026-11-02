# Candidate Bridge Workflow

## Purpose
`CandidateVerificationBridge` connects `php_taint_trace` detector candidates to live debugger evidence capture.

It is designed for this flow:
1. `php_taint_trace` emits candidate JSONL records.
2. Bridge loads candidates.
3. For each candidate, caller triggers target request.
4. SDK captures snapshot, execution trace, and transcript artifact.
5. Artifact output can be consumed by verifier/scoring systems.

## Input Contract
Bridge loader accepts JSONL lines in any of these forms:
- envelope with `candidates: []`
- object with `candidate: {}`
- direct candidate object

Bridge normalization also consumes nested detector schema fields when present:
- `request_evidence.request_uri`
- `candidate_snapshot.request_evidence.request_uri`
- `sink_evidence.sink_name` / `sink_evidence.sink_category`
- envelope-level `request_uri` fallback for candidate rows missing explicit request URI

Recognized candidate id keys:
- `candidate_id`
- `candidateId`
- `id`

## Output Contract
Per candidate:
- `candidateId`
- `correlationId` (defaults to `candidateId` when absent)
- `requestId` / `findingId` (when present in source envelope)
- `appliedPolicyPack`
- `appliedCaptureProfile`
- `sessionId`
- `artifactPath` (`dbgp-transcript.v1` JSON)
- optional `snapshot`
- optional `trace`
- `errors[]`

## CLI Usage
```bash
npx tsx src/cli.ts bridge-candidates \
  --candidates-jsonl ./runtime/candidates.jsonl \
  --trigger-cmd 'curl -s http://127.0.0.1:8080/?candidate=${candidateId}' \
  --artifacts-dir ./.dbgp_bridge_artifacts \
  --trace-steps 0 \
  --capture-profile rce \
  --policy-pack default \
  --watch '$cmd' \
  --trigger-resolver-plugin ./examples/plugins/custom-trigger-resolver-plugin.ts \
  --redaction-plugin ./examples/plugins/custom-redaction-plugin.ts \
  --output json
```

`--trace-steps 0` means “use selected capture-profile default (fall back to policy-pack default).”

## Placeholder Expansion
`--trigger-cmd` supports:
- `${candidateId}`
- `${sinkCategory}`
- `${sinkName}`
- `${requestUri}`
- `${correlationId}`
- `${requestId}`
- `${findingId}`

Values are shell-escaped before substitution.

## Policy-Pack Resolution
Bridge policy resolution order:
1. If `--disable-category-policy-pack` is not set, category policy pack (`rce/ssrf/sqli/file/xss/idor`).
2. Otherwise, explicit `--policy-pack`.

Policy pack controls default trace/watch/snapshot behavior and is reported in each bridge result entry.

## Capture-Profile Resolution
Bridge capture-profile resolution order:
1. If `--disable-category-capture-profile` is not set, category capture profile (`rce/ssrf/sqli/file/xss/idor`).
2. Otherwise, explicit `--capture-profile`.

Capture profiles control trace action and stop-on-status behavior and are reported in each bridge result entry.
