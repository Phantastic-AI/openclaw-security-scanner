# OpenClaw Scanner (OCS) Smoke Test

Last updated: 2026-03-25
Canonical spec: [OPENCLAW-SCANNER-SPEC.md](./OPENCLAW-SCANNER-SPEC.md)

This is a maintainer-facing live smoke guide. Keep run-specific host notes, prefixes, and dated evidence in your ops docs or ticket history, not here.

This plugin has one repeatable pod smoke path with two phases:

- the live `messaging` gateway for `allow / ask / approve / deny`
- the coding-profile canary gateway for scan-daemon-backed download and package-install scans

For the lower-level scan-only canary notes, use [ANTIVIRUS-SMOKE-TEST.md](./ANTIVIRUS-SMOKE-TEST.md).

## What this smoke covers

Main messaging gateway:

- `allow`: a benign local tool call should pass
- `ask`: a high-impact outbound action should block and request approval
- `allow once`: the exact pending action should be allowed once after a natural-language approval reply
- `deny`: a natural-language refusal should keep the action from being retried

Exec-capable canary gateway:

- `posture-report`: exec-capable profile must report `degraded_exec_posture`
- `download`: scan-daemon-backed ClamAV path should record `clean`
- `package install`: scan-daemon-backed ClamAV path should record `clean`
- `package install`: scan-daemon-backed OSV path should record `advisory` for `minimist@0.0.8`
- optional `fail closed`: stopping `openclaw-scand` must stop the actual package install from mutating the workspace

## What this smoke does not prove

- hard shell-block coverage like `rm -rf`
- browser or web ingress
- sandboxed exec attestation
- perfect user-facing wording for blocked exec-package actions when the scan daemon is down

## One-command smoke

```bash
./smoke/smoke_remote_scanner.sh <host-or-pod-ip>
```

Optional session prefix:

```bash
./smoke/smoke_remote_scanner.sh <host-or-pod-ip> my-smoke
```

Include the negative scan-daemon-required check:

```bash
SMOKE_INCLUDE_SCAN_DAEMON_FAILCLOSED=1 ./smoke/smoke_remote_scanner.sh <host-or-pod-ip> my-smoke
```

## How to read the results

- `allow` should return a normal assistant answer after using `sessions_list`.
- `ask` should show the `sessions_send` attempt blocked for approval.
- `allow once` passes when:
  - the assistant says the send was delivered
  - the security log contains `approval_granted`
  - the security log contains `egress_allow_approved`
  - the ask-session transcript shows the second `sessions_send` call accepted
- `deny` passes when:
  - the assistant refuses to retry
  - the deny approval-store entry is `state: "denied"`
- the canary `posture-report` must show `degraded_exec_posture`
- the canary `antivirus-report` must show `transport: "openclaw-scand"` and `verdict: "clean"` for the download and package-install sessions
- the canary `sca-report` must show `transport: "openclaw-scand"` and `verdict: "advisory"` for the `minimist@0.0.8` package-install session
- the optional scan-daemon-required negative check passes only if the workspace check prints `MISSING`

Important caveat:

- on current OpenClaw builds, the negative exec-package phase can still end with the assistant guessing the package name even when OCS blocked the real tool result
- for that phase, the source of truth is:
  - workspace path remains absent
  - antivirus/SCA ledgers record `unavailable`
  - no new scan-daemon log record appears for the blocked action

## Troubleshooting

- The smoke harness sets `OPENCLAW_GATEWAY_PORT=19011` for the canary. Do not drop that env or the CLI may drift back to the main `18789` gateway.
- If `gateway call ...` returns websocket `1006`, the gateway usually was not fully ready yet after restart. Rerun after `gateway call status --timeout 30000 --json` succeeds.
- If approval review fails with `401 Unauthorized`, check whether the systemd env token and `openclaw.json` token differ. The plugin now prefers the configured gateway auth token for local HTTP review and logs a mismatch warning.
- Prefer `sessions_send` over stack-specific chat tools when you want a repeatable approval smoke.
- Restart the real runtime-user gateway service, not an arbitrary shell wrapper, if the main gateway needs to be recycled.
- The canary is usually a separate background process, not the main user service. If you cycle it manually, preserve its state dir, config path, and dedicated gateway port.
