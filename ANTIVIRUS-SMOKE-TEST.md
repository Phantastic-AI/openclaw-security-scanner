# OCS Antivirus Smoke Test

Last updated: 2026-03-22
Canonical spec: [OPENCLAW-SCANNER-SPEC.md](./OPENCLAW-SCANNER-SPEC.md)

This protocol verifies OCS antivirus behavior on a real pod host in two states:

- without a usable ClamAV daemon
- with `clamd` installed and healthy

It uses a coding-profile canary because messaging-profile pods do not expose `exec`.

## What this smoke proves

- file-producing shell actions are detected by OCS
- OCS records `unavailable` when no antivirus daemon is usable
- OCS records `clean` with `protection=triggered` when `clamd` is reachable
- the pod workspace is actually mutated by the `npm install` action in both runs

## What this smoke does not prove

- fanotify / `clamonacc` on-access enforcement
- malware quarantine behavior
- perfect user-visible inline warning delivery on every deployed OpenClaw build

## Canary Setup

Use an isolated state dir on the pod host so the smoke does not disturb the live messaging gateway.

Recommended canary state:

- `OPENCLAW_STATE_DIR=/home/openclaw/.openclaw-avsmoke`
- `OPENCLAW_CONFIG_PATH=/home/openclaw/.openclaw-avsmoke/openclaw.json`
- `tools.profile = "coding"`
- no channel plugins
- OCS enabled from `/home/openclaw/.openclaw-avsmoke/extensions/openclaw-scanner`
- loopback gateway on a separate port such as `19011`

## No-ClamAV Smoke

1. Ensure there is no usable daemon:
   - `command -v clamd` should fail or `/run/clamav/clamd.ctl` should be absent.
2. Clear old canary evidence:
   - remove the test workspace directory
   - remove `antivirus-status.json`
   - remove `antivirus-ledger.json`
3. Run a real file-producing command through the agent:

```bash
env OPENCLAW_STATE_DIR=/home/openclaw/.openclaw-avsmoke \
    OPENCLAW_CONFIG_PATH=/home/openclaw/.openclaw-avsmoke/openclaw.json \
    node /home/openclaw/code/openclaw/dist/index.js gateway call agent --expect-final --json --params '{
      "sessionKey":"agent:main:avsmoke-no-clam",
      "idempotencyKey":"avsmoke-no-clam-1",
      "message":"Use the exec tool to run this exact command in the workspace and then summarize the result: mkdir -p /home/openclaw/.openclaw-avsmoke/workspace/av-no-clam && cd /home/openclaw/.openclaw-avsmoke/workspace/av-no-clam && printf '\''{\"name\":\"av-no-clam\",\"version\":\"1.0.0\"}\n'\'' > package.json && npm install is-number@7.0.0"
    }'
```

Expected evidence:

- workspace contains `av-no-clam/package.json`, `package-lock.json`, and `node_modules/is-number`
- `~/.openclaw-avsmoke/plugins/openclaw-scanner/antivirus-status.json` reports:
  - `status: "unavailable"`
  - `protection: "unavailable"`
- `~/.openclaw-avsmoke/plugins/openclaw-scanner/antivirus-ledger.json` contains a record with:
  - `verdict: "unavailable"`
  - `actionKind: "package install"`
- gateway log contains `event":"antivirus_unavailable"`

## With-ClamAV Smoke

1. Install packages on the pod host:

```bash
sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y clamav clamav-daemon
```

2. Wait for databases, then start the daemon:

```bash
sudo systemctl status clamav-freshclam --no-pager
sudo systemctl restart clamav-daemon
sudo systemctl status clamav-daemon --no-pager
ls -la /run/clamav
```

Expected daemon evidence:

- `/var/lib/clamav/main.cvd` exists
- `/var/lib/clamav/daily.cvd` exists
- `clamav-daemon.service` is `active (running)`
- `/run/clamav/clamd.ctl` exists

3. Clear old canary evidence:
   - remove the test workspace directory
   - remove `antivirus-status.json`
   - remove `antivirus-ledger.json`
4. Run another real file-producing command through the agent:

```bash
env OPENCLAW_STATE_DIR=/home/openclaw/.openclaw-avsmoke \
    OPENCLAW_CONFIG_PATH=/home/openclaw/.openclaw-avsmoke/openclaw.json \
    node /home/openclaw/code/openclaw/dist/index.js gateway call agent --expect-final --json --params '{
      "sessionKey":"agent:main:avsmoke-with-clam",
      "idempotencyKey":"avsmoke-with-clam-1",
      "message":"Use the exec tool to run this exact command in the workspace and then summarize the result: mkdir -p /home/openclaw/.openclaw-avsmoke/workspace/av-with-clam && cd /home/openclaw/.openclaw-avsmoke/workspace/av-with-clam && printf '\''{\"name\":\"av-with-clam\",\"version\":\"1.0.0\"}\n'\'' > package.json && npm install is-odd@3.0.1"
    }'
```

Expected evidence:

- workspace contains `av-with-clam/package.json`, `package-lock.json`, and `node_modules/is-odd`
- `~/.openclaw-avsmoke/plugins/openclaw-scanner/antivirus-status.json` reports:
  - `status: "active"`
  - `protection: "triggered"`
  - `socketPath: "/run/clamav/clamd.ctl"`
- `~/.openclaw-avsmoke/plugins/openclaw-scanner/antivirus-ledger.json` contains a record with:
  - `verdict: "clean"`
  - `protection: "triggered"`
  - `scannedPaths` populated
- gateway log contains `event":"antivirus_scan_clean"`
- there should be no new `antivirus_unavailable` event for the with-ClamAV run

## Reporting Commands

Repo-local report script:

```bash
node scripts/print_antivirus_report.mjs --state-dir ~/.openclaw/plugins/openclaw-scanner
```

Live canary report on the pod host:

```bash
cat /home/openclaw/.openclaw-avsmoke/plugins/openclaw-scanner/antivirus-status.json
cat /home/openclaw/.openclaw-avsmoke/plugins/openclaw-scanner/antivirus-ledger.json
```

## Verified Live Notes

Verified on `51.210.13.102` on March 22, 2026 UTC:

- the live messaging gateway was not suitable for AV smoke because it only exposed messaging/session tools
- the smoke used an isolated coding-profile canary gateway under `~/.openclaw-avsmoke`
- no-ClamAV run recorded `unavailable` and still completed the `npm install`
- with-ClamAV run recorded `clean` with `protection=triggered`

Verified on Vince pod `51.210.14.27` on March 22, 2026 UTC with OpenClaw `2026.3.14`:

- benign `npm install` egress review no longer blocks on truncated `/v1/responses` output because OCS falls back to `chatCompletions`
- no-ClamAV run recorded `status=unavailable`, `protection=unavailable`, and the warning text in the antivirus ledger/report while the final assistant reply still failed to surface that warning
- with-ClamAV run recorded `status=active`, `protection=triggered`, `verdict=clean`, and the final assistant reply correctly reported that no antivirus warning applied

## Known Compatibility Gaps On OpenClaw 2026.3.2

- plugin subagent review transport was not usable on the deployed pod build, so the canary used local loopback HTTP review instead
- plugin CLI registration for `openclaw ocs ...` was not exposed on the deployed pod build even though repo tests pass
- live `after_tool_call` payloads on this pod build did not carry reliable `sessionKey` / `toolCallId` attribution into the antivirus ledger
- Gemini did not reliably echo the unavailable-scan warning in the final assistant reply even when OCS injected warning context; the ledger and gateway log were the source of truth for the no-ClamAV canary

## Known Compatibility Gap On OpenClaw 2026.3.14

- on Vince's latest available `2026.3.14` build, no-ClamAV detection, ledger/report output, and benign egress review all work, but the final assistant reply still does not reliably surface the unavailable-scan warning even when OCS injects warning context before the next model turn
