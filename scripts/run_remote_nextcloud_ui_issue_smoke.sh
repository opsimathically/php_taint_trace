#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_PATH="${PHP_TAINT_TRACE_TEST_CONFIG:-${XDG_CONFIG_HOME:-${HOME}/.config}/php_taint_trace/testing_container_config.json}"
HOST_LABEL="${PHP_TAINT_TRACE_TEST_HOST_LABEL:-lab.example.invalid}"
UI_PORT="${PHP_TAINT_TRACE_REMOTE_UI_DAEMON_PORT:-19120}"
NEXTCLOUD_PORT="${PHP_TAINT_TRACE_REMOTE_NEXTCLOUD_PORT:-19135}"
REMOTE_TAINT_ROOT="${PHP_TAINT_TRACE_REMOTE_TAINT_ROOT:-/opt/php_taint_trace_vuln_lab/rewrite}"
REMOTE_NEXTCLOUD_ROOT="${PHP_TAINT_TRACE_REMOTE_NEXTCLOUD_ROOT:-/opt/php_audit_apps/nextcloud/current}"
REMOTE_VERIFIER_DIR="${PHP_TAINT_TRACE_REMOTE_NEXTCLOUD_VERIFIER_DIR:-/opt/php_audit_apps/_runtime/nextcloud/verifier}"

usage() {
  cat <<'USAGE'
Usage: scripts/run_remote_nextcloud_ui_issue_smoke.sh [options]

Options:
  --config PATH          External host credential JSON (default: PHP_TAINT_TRACE_TEST_CONFIG or XDG config directory)
  --host-label LABEL     Host label in config (default: lab.example.invalid)
  --ui-port PORT         Visualizer UI daemon port (default: 19120)
  --nextcloud-port PORT  Nextcloud app port (default: 19135)
  --help                 Show help

This smoke test proves Nextcloud can generate a real taint/sink issue that appears in the visualizer UI.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)
      CONFIG_PATH="$2"
      shift 2
      ;;
    --host-label)
      HOST_LABEL="$2"
      shift 2
      ;;
    --ui-port)
      UI_PORT="$2"
      shift 2
      ;;
    --nextcloud-port)
      NEXTCLOUD_PORT="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

for cmd in python3 ssh sshpass; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "Missing required local command: ${cmd}" >&2
    exit 1
  fi
done

if [[ ! -f "${CONFIG_PATH}" ]]; then
  echo "Config file not found: ${CONFIG_PATH}" >&2
  exit 1
fi

mapfile -t _cfg < <(python3 - "${CONFIG_PATH}" "${HOST_LABEL}" <<'PY'
import json
import sys
from pathlib import Path

cfg_path = Path(sys.argv[1])
label = sys.argv[2]
data = json.loads(cfg_path.read_text())
if label not in data:
    raise SystemExit(f"Host label not found in config: {label}")
entry = data[label]
required = ("ipv4", "ssh_username", "ssh_password", "sudopassword")
missing = [k for k in required if k not in entry or not str(entry[k]).strip()]
if missing:
    raise SystemExit(f"Missing required config keys for {label}: {', '.join(missing)}")
print(entry["ipv4"])
print(entry["ssh_username"])
print(entry["ssh_password"])
print(entry["sudopassword"])
PY
)

HOST="${_cfg[0]}"
SSH_USER="${_cfg[1]}"
SSH_PASSWORD="${_cfg[2]}"
SUDO_PASSWORD="${_cfg[3]}"

SSH_OPTS=(
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o PubkeyAuthentication=no
  -o PreferredAuthentications=password
  -o NumberOfPasswordPrompts=1
  -o ConnectTimeout=20
)

ssh_exec() {
  sshpass -p "${SSH_PASSWORD}" ssh "${SSH_OPTS[@]}" "${SSH_USER}@${HOST}" "$@"
}

REMOTE_CMD="$(printf \
  "UI_PORT=%q NEXTCLOUD_PORT=%q REMOTE_TAINT_ROOT=%q REMOTE_NEXTCLOUD_ROOT=%q REMOTE_VERIFIER_DIR=%q SUDOPASS=%q bash -s" \
  "${UI_PORT}" \
  "${NEXTCLOUD_PORT}" \
  "${REMOTE_TAINT_ROOT}" \
  "${REMOTE_NEXTCLOUD_ROOT}" \
  "${REMOTE_VERIFIER_DIR}" \
  "${SUDO_PASSWORD}" \
)"

echo "[nextcloud-ui-smoke] running on ${HOST} (nextcloud:${NEXTCLOUD_PORT} ui:${UI_PORT})"
ssh_exec "${REMOTE_CMD}" <<'REMOTE'
set -euo pipefail

run_sudo() {
  sudo -S -k -p '' "$@" <<<"${SUDOPASS}"
}

NEXTCLOUD_WEB_ROOT="${REMOTE_NEXTCLOUD_ROOT}"
PROBE_FILE="${NEXTCLOUD_WEB_ROOT}/ptt_nextcloud_ui_smoke.php"
DECISIONS_PATH="${REMOTE_VERIFIER_DIR}/decisions.jsonl"
JOBS_PATH="${REMOTE_VERIFIER_DIR}/jobs.jsonl"
UI_CONFIG_PATH="/etc/php_taint_trace/visualizer_ui_daemon.json"
UI_DECISIONS_PATH="${DECISIONS_PATH}"

run_sudo mkdir -p "${REMOTE_VERIFIER_DIR}"
run_sudo touch "${DECISIONS_PATH}" "${JOBS_PATH}"

if run_sudo test -f "${UI_CONFIG_PATH}"; then
  UI_DECISIONS_PATH="$(run_sudo python3 -c 'import json,sys; doc=json.load(open(sys.argv[1], "r", encoding="utf-8")); print((doc.get("fileSources") or {}).get("decisionsWorkerPath") or "")' "${UI_CONFIG_PATH}")"
  if [[ -z "${UI_DECISIONS_PATH}" ]]; then
    UI_DECISIONS_PATH="${DECISIONS_PATH}"
  fi
  run_sudo mkdir -p "$(dirname "${UI_DECISIONS_PATH}")"
  run_sudo touch "${UI_DECISIONS_PATH}"
fi
echo "[nextcloud-ui-smoke] ui_decisions_path=${UI_DECISIONS_PATH}" >&2

TOKEN="nextcloud_smoke_$(date +%s)_$RANDOM"
MARKER="xtanzi_nextcloud_ui_smoke_${TOKEN}"
REQUEST_URI="/ptt_nextcloud_ui_smoke.php?ptt_nextcloud_smoke=${TOKEN}&cmd=echo%20${MARKER}"

TMP_PROBE="$(mktemp)"
cat > "${TMP_PROBE}" <<'PHP'
<?php
declare(strict_types=1);
if (!isset($_GET['ptt_nextcloud_smoke']) || !hash_equals('__TOKEN__', (string) $_GET['ptt_nextcloud_smoke'])) {
    http_response_code(404);
    exit;
}
$cmd = isset($_GET['cmd']) ? (string) $_GET['cmd'] : '';
if ($cmd !== '') {
    @system($cmd);
}
echo 'ok';
PHP
sed -i "s/__TOKEN__/${TOKEN}/g" "${TMP_PROBE}"
run_sudo install -m 0644 "${TMP_PROBE}" "${PROBE_FILE}"
run_sudo chown www-data:www-data "${PROBE_FILE}" || true
rm -f "${TMP_PROBE}"

cleanup() {
  run_sudo rm -f "${PROBE_FILE}"
}
trap cleanup EXIT

HTTP_CODE="$(curl -sS -o /tmp/nextcloud_ui_smoke_response.txt -w '%{http_code}' "http://127.0.0.1:${NEXTCLOUD_PORT}${REQUEST_URI}" || true)"
if [[ "${HTTP_CODE}" != "200" ]]; then
  echo "Nextcloud smoke trigger returned HTTP ${HTTP_CODE}" >&2
  head -c 500 /tmp/nextcloud_ui_smoke_response.txt >&2 || true
  rm -f /tmp/nextcloud_ui_smoke_response.txt
  exit 1
fi
rm -f /tmp/nextcloud_ui_smoke_response.txt

python3 - "${JOBS_PATH}" "${TOKEN}" "${REQUEST_URI}" > /tmp/nextcloud_ui_smoke_candidate.json <<'PY'
import json
import sys
from pathlib import Path
import time

path = Path(sys.argv[1])
token = sys.argv[2]
request_uri = sys.argv[3]

deadline = time.time() + 90.0
matched = None
while time.time() < deadline and matched is None:
    lines = path.read_text(encoding='utf-8').splitlines()
    for raw in reversed(lines):
        raw = raw.strip()
        if not raw:
            continue
        if token not in raw:
            continue
        try:
            row = json.loads(raw)
        except Exception:
            continue
        snapshot = row.get("candidate_snapshot") or {}
        sink = snapshot.get("sink_evidence") or {}
        meta = sink.get("metadata") or {}
        stack = meta.get("stacktrace") or []

        has_probe_file = False
        for frame in stack:
            if not isinstance(frame, dict):
                continue
            file_uri = frame.get("file_uri")
            if isinstance(file_uri, str) and file_uri.endswith("/ptt_nextcloud_ui_smoke.php"):
                has_probe_file = True
                break
        if not has_probe_file:
            continue

        if snapshot.get("sink_name") != "system":
            continue

        candidate_id = row.get("candidate_id")
        if not isinstance(candidate_id, str) or not candidate_id:
            continue

        matched = {
            "candidate_id": candidate_id,
            "sink_category": row.get("sink_category") or snapshot.get("sink_category") or "rce",
            "sink_name": snapshot.get("sink_name") or "system",
            "job_id": row.get("job_id"),
            "request_uri": request_uri,
            "stacktrace": (meta.get("stacktrace") if isinstance(meta.get("stacktrace"), list) else []),
            "stacktrace_captured_at": meta.get("stacktrace_captured_at"),
        }
        break
    if matched is None:
        time.sleep(0.5)

if matched is None:
    raise SystemExit("No new verifier job found for the Nextcloud smoke request.")

print(json.dumps(matched))
PY

run_sudo env \
  PHP_TAINT_TRACE_VERIFIER_RUNTIME_DIR="${REMOTE_VERIFIER_DIR}" \
  PHP_TAINT_TRACE_VERIFIER_REPLAY_TARGET=local \
  PHP_TAINT_TRACE_VERIFIER_LOCAL_BASE_URL="http://127.0.0.1:${NEXTCLOUD_PORT}" \
  php "${REMOTE_TAINT_ROOT}/scripts/run_verifier_worker.php" --drain --max-cycles=40 >/tmp/run_remote_nextcloud_ui_issue_smoke_worker.log 2>&1

python3 - "${UI_PORT}" /tmp/nextcloud_ui_smoke_candidate.json <<'PY'
import json
import sys
import time
import urllib.request

ui_port = int(sys.argv[1])
candidate = json.loads(open(sys.argv[2], "r", encoding="utf-8").read())
target_candidate_id = candidate["candidate_id"]
found = None
issues_payload = None
for _ in range(80):
    with urllib.request.urlopen(f"http://127.0.0.1:{ui_port}/api/v1/issues", timeout=5) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    issues = payload.get("issues") or []
    for issue in issues:
        cid = issue.get("candidateId")
        if isinstance(cid, str) and cid == target_candidate_id:
            found = issue
            issues_payload = payload
            break
    if found is not None:
        break
    time.sleep(0.5)

if found is None:
    raise SystemExit("UI did not surface a newly generated Nextcloud candidate issue.")

with urllib.request.urlopen(f"http://127.0.0.1:{ui_port}/api/v1/issues/{target_candidate_id}", timeout=5) as resp:
    detail = json.loads(resp.read().decode("utf-8"))

issue = detail.get("issue") or {}
decision = issue.get("decision") or {}
metadata = decision.get("metadata") if isinstance(decision, dict) else {}
stacktrace = metadata.get("stacktrace") if isinstance(metadata, dict) else None
if not isinstance(stacktrace, list) or not stacktrace:
    raise SystemExit("UI issue detail did not include stacktrace metadata.")

has_probe_frame = False
for frame in stacktrace:
    if not isinstance(frame, dict):
        continue
    file_uri = frame.get("file_uri")
    if isinstance(file_uri, str) and file_uri.endswith("/ptt_nextcloud_ui_smoke.php"):
        has_probe_frame = True
        break

if not has_probe_frame:
    raise SystemExit("UI stacktrace metadata did not include Nextcloud probe path.")

print(json.dumps({
    "ok": True,
    "candidateId": found.get("candidateId"),
    "sinkCategory": found.get("sinkCategory"),
    "outcome": found.get("outcome"),
    "confidence": found.get("confidence"),
    "triage": found.get("triageStatus"),
    "stacktraceFrames": len(stacktrace),
    "totalIssuesVisible": len((issues_payload or {}).get("issues") or []),
}, indent=2))
PY

rm -f /tmp/nextcloud_ui_smoke_candidate.json
echo "nextcloud-ui-smoke: PASS token=${TOKEN}"
REMOTE

echo "[nextcloud-ui-smoke] PASS"
