#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <host> [session-prefix]" >&2
  exit 1
fi

HOST="$1"
PREFIX="${2:-smoke-$(date +%s)}"
REMOTE_OPENCLAW="node /home/openclaw/code/openclaw/dist/index.js"

remote() {
  ssh -o BatchMode=yes "debian@${HOST}" "sudo -u openclaw bash -lc $(
    printf '%q' "$1"
  )"
}

wait_gateway_ready() {
  local attempt
  for attempt in $(seq 1 20); do
    if remote "${REMOTE_OPENCLAW} gateway call status --json >/dev/null" >/dev/null 2>&1; then
      echo "gateway ready on attempt ${attempt}"
      return 0
    fi
    sleep 2
  done
  echo "gateway did not become ready on ${HOST}" >&2
  return 1
}

run_agent_best_effort() {
  local session_key="$1"
  local idempotency_key="$2"
  local message="$3"
  remote "env SMOKE_SESSION_KEY='${session_key}' SMOKE_IDEMPOTENCY_KEY='${idempotency_key}' SMOKE_MESSAGE='${message}' python3 - <<'PY'
import json, os, subprocess, sys
params = {
  'message': os.environ['SMOKE_MESSAGE'],
  'sessionKey': os.environ['SMOKE_SESSION_KEY'],
  'idempotencyKey': os.environ['SMOKE_IDEMPOTENCY_KEY'],
}
cmd = ['node', '/home/openclaw/code/openclaw/dist/index.js', 'gateway', 'call', 'agent', '--expect-final', '--json', '--params', json.dumps(params)]
proc = subprocess.run(cmd, capture_output=True, text=True)
print(proc.stdout, end='')
if proc.stderr:
    print(proc.stderr, file=sys.stderr, end='')
print(f'[smoke] returncode={proc.returncode}')
PY"
}

show_session_id() {
  local session_key="$1"
  remote "python3 - <<'PY'
import json
from pathlib import Path
session_key = '${session_key}'
sessions = json.loads(Path('/home/openclaw/.openclaw/agents/main/sessions/sessions.json').read_text())
if isinstance(sessions, dict):
    if session_key in sessions and isinstance(sessions[session_key], dict):
        print(sessions[session_key].get('sessionId') or sessions[session_key].get('id') or '')
    else:
        recent = sessions.get('recent', []) if isinstance(sessions.get('recent'), list) else []
        for item in recent:
            if item.get('key') == session_key:
                print(item.get('sessionId') or item.get('id') or '')
                break
elif isinstance(sessions, list):
    for item in sessions:
        if isinstance(item, dict) and item.get('key') == session_key:
            print(item.get('sessionId') or item.get('id') or '')
            break
PY"
}

show_transcript_tail() {
  local session_key="$1"
  local session_id
  session_id="$(show_session_id "${session_key}")"
  if [[ -z "${session_id}" ]]; then
    echo "no session id found for ${session_key}" >&2
    return 1
  fi
  remote "python3 - <<'PY'
import json
from pathlib import Path
session_id = '${session_id}'
p = Path(f'/home/openclaw/.openclaw/agents/main/sessions/{session_id}.jsonl')
for line in p.read_text().splitlines()[-20:]:
    obj = json.loads(line)
    print(json.dumps(obj, ensure_ascii=False))
PY"
}

show_approval_state() {
  local session_key="$1"
  remote "python3 - <<'PY'
import json
from pathlib import Path
session_key = '${session_key}'
p = Path('/home/openclaw/.openclaw/plugins/openclaw-scanner/approval-store.json')
payload = json.loads(p.read_text())
entries = payload.get('entries', {})
matches = False
for key, value in entries.items():
    blob = json.dumps(value, ensure_ascii=False)
    if session_key in key or session_key in blob:
        matches = True
        print(key)
        print(json.dumps(value, indent=2, ensure_ascii=False))
if not matches:
    print(f'(no approval-store entry for {session_key})')
PY"
}

show_security_log_tail() {
  remote "python3 - <<'PY'
from pathlib import Path
log_path = Path('/tmp/openclaw-999/openclaw-$(date +%F).log')
lines = [line.rstrip() for line in log_path.read_text().splitlines() if 'openclaw-scanner' in line]
for line in lines[-30:]:
    print(line)
PY"
}

wait_gateway_ready

ALLOW_SESSION="agent:main:${PREFIX}-allow"
ASK_SESSION="agent:main:${PREFIX}-ask"
DENY_SESSION="agent:main:${PREFIX}-deny"

echo
echo "== Allow case =="
run_agent_best_effort \
  "${ALLOW_SESSION}" \
  "${PREFIX}-allow" \
  "Use the sessions_list tool and reply with the total session count only."

echo
echo "== Ask case =="
run_agent_best_effort \
  "${ASK_SESSION}" \
  "${PREFIX}-ask-1" \
  "Use the sessions_send tool to send the exact text ${PREFIX} approval smoke to this same session key ${ASK_SESSION} with timeoutSeconds 0. Do not do anything else."

echo
echo "== Allow-once after approval =="
run_agent_best_effort \
  "${ASK_SESSION}" \
  "${PREFIX}-ask-2" \
  "Yes, send it now."

echo
echo "== Deny case =="
run_agent_best_effort \
  "${DENY_SESSION}" \
  "${PREFIX}-deny-1" \
  "Use the sessions_send tool to send the exact text ${PREFIX} denial smoke to this same session key ${DENY_SESSION} with timeoutSeconds 0. Do not do anything else."
run_agent_best_effort \
  "${DENY_SESSION}" \
  "${PREFIX}-deny-2" \
  "No, do not send it."

echo
echo "== Security log tail =="
show_security_log_tail

echo
echo "== Ask approval state =="
show_approval_state "${ASK_SESSION}"

echo
echo "== Deny approval state =="
show_approval_state "${DENY_SESSION}"

echo
echo "== Ask transcript tail =="
show_transcript_tail "${ASK_SESSION}"

echo
echo "== Deny transcript tail =="
show_transcript_tail "${DENY_SESSION}"

echo
echo "== Allow transcript tail =="
show_transcript_tail "${ALLOW_SESSION}"
