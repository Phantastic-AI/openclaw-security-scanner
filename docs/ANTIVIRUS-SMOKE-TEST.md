# OCS Antivirus And Package-Scan Smoke Test

Last updated: 2026-03-25
Canonical spec: [OPENCLAW-SCANNER-SPEC.md](./OPENCLAW-SCANNER-SPEC.md)

This is a maintainer-facing exec-canary smoke guide. Keep host-specific notes and dated run evidence outside this public doc.

This protocol verifies the exec-capable canary path on a real pod host:

- scan-daemon-backed ClamAV download scanning
- scan-daemon-backed ClamAV package-install scanning
- scan-daemon-backed OSV package SCA
- optional scan-daemon-required fail-closed behavior

It uses a coding-profile canary because messaging-profile pods do not expose `exec`.

## What this smoke proves

- file-producing shell actions are detected by OCS
- `openclaw-scand` is the transport for scan-backed exec actions
- OCS records `clean` with `protection=triggered` when `clamd` is reachable
- OCS records `advisory` for a known vulnerable npm dependency through OSV
- scan-daemon-required mode can stop the real package-install side effect even if the assistant reply is misleading

## What this smoke does not prove

- fanotify / `clamonacc` on-access enforcement
- malware quarantine behavior
- perfect user-visible inline warning delivery on every deployed OpenClaw build
- malicious-package heuristics beyond ClamAV and OSV

## Canary Setup

Use an isolated state dir on the pod host so the smoke does not disturb the live messaging gateway.

Recommended canary state:

- `OPENCLAW_STATE_DIR=<runtime-home>/.openclaw-avsmoke`
- `OPENCLAW_CONFIG_PATH=<runtime-home>/.openclaw-avsmoke/openclaw.json`
- `OPENCLAW_GATEWAY_PORT=19011`
- `tools.profile = "coding"`
- no channel plugins
- OCS enabled from the canary state's `extensions/openclaw-scanner`
- loopback gateway on a separate port such as `19011`

## Preferred Smoke Command

From the ops repo on the controller host:

```bash
SMOKE_INCLUDE_SCAN_DAEMON_FAILCLOSED=1 ./smoke/smoke_remote_scanner.sh <host-or-pod-ip> qa-smoke
```

Expected evidence:

- `posture-report` shows `degraded_exec_posture`
- the download session writes `scand-download/example.html`
- `~/.openclaw-avsmoke/plugins/openclaw-scanner/antivirus-status.json` reports:
  - `status: "active"`
  - `protection: "triggered"`
  - `transport: "openclaw-scand"`
- `~/.openclaw-avsmoke/plugins/openclaw-scanner/antivirus-ledger.json` contains a download record with:
  - `verdict: "clean"`
  - `protection: "triggered"`
  - `transport: "openclaw-scand"`
- the package-install session writes `scand-npm/package-lock.json`
- `~/.openclaw-avsmoke/plugins/openclaw-scanner/antivirus-ledger.json` contains a package-install record with:
  - `verdict: "clean"`
  - `transport: "openclaw-scand"`
- `~/.openclaw-avsmoke/plugins/openclaw-scanner/sca-ledger.json` contains a package-install record with:
  - `verdict: "advisory"`
  - `transport: "openclaw-scand"`
  - advisory ids `GHSA-vh95-rmgr-6w4m` and `GHSA-xvch-5gv4-984h`
- `/var/log/openclaw-scand/scans.jsonl` contains one `malware_scan` record and one `package_sca` record for the package-install session
- with `SMOKE_INCLUDE_SCAN_DAEMON_FAILCLOSED=1`, the negative phase passes only if:
  - the workspace check prints `MISSING`
  - the scan-daemon log does not get a new record for the blocked action

## Reporting Commands

Repo-local report script:

```bash
node scripts/print_antivirus_report.mjs --state-dir ~/.openclaw/plugins/openclaw-scanner
```

Live canary report on the pod host:

```bash
env OPENCLAW_STATE_DIR=<runtime-home>/.openclaw-avsmoke \
    OPENCLAW_CONFIG_PATH=<runtime-home>/.openclaw-avsmoke/openclaw.json \
    OPENCLAW_GATEWAY_PORT=19011 \
    openclaw ocs antivirus-report --json --limit 20

env OPENCLAW_STATE_DIR=<runtime-home>/.openclaw-avsmoke \
    OPENCLAW_CONFIG_PATH=<runtime-home>/.openclaw-avsmoke/openclaw.json \
    OPENCLAW_GATEWAY_PORT=19011 \
    openclaw ocs sca-report --json --limit 20

env OPENCLAW_STATE_DIR=<runtime-home>/.openclaw-avsmoke \
    OPENCLAW_CONFIG_PATH=<runtime-home>/.openclaw-avsmoke/openclaw.json \
    OPENCLAW_GATEWAY_PORT=19011 \
    openclaw ocs posture-report --json
```

## Compatibility Notes

Keep build-specific breakage and dated pod evidence in release notes or ticket history, not here.

The two compatibility patterns still worth remembering are:

- older OpenClaw builds may require HTTP fallback if the subagent review transport is unavailable
- some builds still fail to surface unavailable-scan warnings reliably in the final assistant reply, so the ledger and scanner reports remain the source of truth
