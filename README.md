# OpenClaw Scanner (OCS)

[![npm version](https://img.shields.io/npm/v/openclaw-scanner)](https://www.npmjs.com/package/openclaw-scanner)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

OpenClaw-native scanner plugin for:

- **Ingress Guard**: review untrusted tool output before the next model turn
- **Egress Guard**: block obviously unsafe tool actions before they run
- **Antivirus Integration**: [ClamAV](https://www.clamav.net/)-backed file scanning for package installs, downloads, and archive extraction

Install from npm through OpenClaw:

```bash
openclaw plugins install openclaw-scanner
```

Links:

- [OpenClaw](https://github.com/openclaw/openclaw) — the agent runtime this plugin extends
- [ClamAV](https://www.clamav.net/) — open-source antivirus engine used for file scanning
- [MoltPod](https://moltpod.com/) — managed cloud hosting for OpenClaw agents

## Mental Model

### 1. Two Guards, Two Doors

```text
┌──────────────────────────────┐         ┌───────────────────────┐         ┌──────────────────────────────┐
│ Outside World                │         │ AI Agent / OpenClaw   │         │ Outside World                │
│ web pages, APIs, tool output │ ─────▶  │ your pod runtime      │ ─────▶  │ email, shell, git, deploys  │
└──────────────────────────────┘         └───────────────────────┘         └──────────────────────────────┘
               ▲                                         ▲                                         ▲
               │                                         │                                         │
        Ingress Guard                             decides what the                           Egress Guard
      "What's coming in?"                         agent actually sees                      "What's going out?"
      - prompt injection?                                                                   - safe to run?
      - hostile instructions?                                                                - secrets or exfil?
      - wrap or quarantine it?                                                               - needs approval?
```

### 2. Ingress Review For Untrusted Tool Output

```text
Agent calls browser tool
        │
        ▼
Gets webpage HTML back
        │
        ▼
Is this tool trusted or untrusted?
(browser = untrusted content source)
        │
        ▼
Ingress review scans the content
┌───────────────┬───────────────┬──────────────────────────┐
│ ALLOW         │ WARN          │ QUARANTINE               │
│ clean         │ suspicious    │ prompt injection         │
├───────────────┼───────────────┼──────────────────────────┤
│ raw content   │ wrapped as    │ replaced with            │
│ passes        │ untrusted     │ "[content quarantined]"  │
│ through       │ reference     │ the agent never sees it  │
│               │ material      │                          │
└───────────────┴───────────────┴──────────────────────────┘
```

### 3. Approval Loop For High-Impact Egress

```text
Agent wants to run: git push --force origin main
        │
        ▼
Egress guard (`policy.mjs`) => finalAction: "ask"
reasonCode: "high_impact_shell_command"
        │
        ▼
OpenClaw runtime only supports "allow" or "block"
so the first attempt becomes a BLOCK with a structured reason
        │
        ▼
Agent tells the user:
"Security requires approval for this action: force push"
        │
        ▼
User replies: "Do it"
        │
        ▼
Approval-intent review records approval for that exact action
        │
        ▼
Agent retries git push --force origin main
        │
        ▼
Egress guard finds the stored approval and ALLOWS it once
```

Canonical design docs:

- [OPENCLAW-SCANNER-SPEC.md](./OPENCLAW-SCANNER-SPEC.md)
- [OPENCLAW-SCANNER-TEST-PLAN.md](./OPENCLAW-SCANNER-TEST-PLAN.md)

PromptScanner is optional. The default path is gateway-backed review using the models already configured on the OpenClaw install.
Gateway review now prefers an internal subagent transport and only falls back to gateway HTTP review when loopback + token auth + explicit review endpoints are safely configured.
If you do not set `trustModel`, `ingressModel`, `egressModel`, or `approvalIntentModel`, the plugin now inherits the pod's configured primary agent model. `approvalIntentModel` falls back to `egressModel` first.

## Current Launch Shape

What it does now:

1. classifies tool trust in `before_tool_call`
2. applies deterministic egress blocking for obvious secret reads and dangerous shell payloads
3. blocks high-impact actions with an approval-required reason and stores one pending approval per exact action
4. stubs untrusted tool results in `tool_result_persist` so raw content is not persisted to the model-visible transcript
5. prefetches ingress review in `after_tool_call`
6. resolves pending tool-result stubs in `before_prompt_build` to:
   - raw content for `allow`
   - wrapped untrusted content for `warn`
   - placeholder-only content for `quarantine`
7. classifies the latest trusted user reply with `approvalIntentModel` so natural-language approval can grant or deny one pending action without exposing hashes to the user
8. re-checks the persisted session transcript inside `before_tool_call` for approval-required retries so the exact pending action can still unblock even when runtime prompt-build messages are sparse or wrapped

Important current constraint:

- OpenClaw's `before_tool_call` hook only supports allow or block
- so plugin-grade `ask` still appears as a block on the first attempt
- the interactive approval loop now happens on the next turn: the plugin reviews the user's latest reply with `approvalIntentModel` and allows the exact pending action once if the user clearly approved it
- live messaging-pod smoke is documented in [SMOKE-TEST.md](./SMOKE-TEST.md)
- routine `git push` is allowed; `git push --force`, `git push -f`, and `git push --force-with-lease` require approval

## Backends

### Default

Use OpenClaw's gateway and review models already configured in the install:

- `trustBackend = gateway`
- `ingressBackend = gateway`
- `egressBackend = gateway`
- optionally set `approvalIntentModel` to a smaller or cheaper model for approval-intent classification

### Optional

Ingress review can use PromptScanner instead:

- `ingressBackend = promptscanner`
- set `apiUrl`, `apiKey`, and `callerId`

## Example Config

Minimal gateway-backed config:

```json
{
  "plugins": {
    "entries": {
      "openclaw-scanner": {
        "enabled": true,
        "config": {
          "ingressBackend": "gateway",
          "egressBackend": "gateway",
          "trustBackend": "gateway",
          "gatewayReviewTransport": "auto",
          "approvalIntentModel": "openai/gpt-5.4-mini"
        }
      }
    }
  }
}
```

Optional PromptScanner ingress config:

```json
{
  "plugins": {
    "entries": {
      "openclaw-scanner": {
        "enabled": true,
        "config": {
          "ingressBackend": "promptscanner",
          "egressBackend": "gateway",
          "trustBackend": "gateway",
          "apiUrl": "https://promptscanner.moltpod.com",
          "apiKey": "${PROMPTSCANNER_API_KEY}",
          "callerId": "pod-a-openclaw",
          "podId": "moltpod-prod-a"
        }
      }
    }
  }
}
```

## Key Config Fields

- `ingressBackend`: `gateway | promptscanner | disabled`
- `egressBackend`: `gateway | disabled`
- `trustBackend`: `gateway | disabled`
- `ingressModel`
- `egressModel`
- `trustModel`
  - defaults to the pod's configured primary model
- `approvalIntentModel`
  - defaults to `egressModel`, then the pod's configured primary model
- `gatewayBaseUrl`
- `gatewayToken`
- `gatewayReviewTransport`: `auto | subagent | http`
- `approvalTtlSec`
- `apiUrl`, `apiKey`, `callerId` for PromptScanner ingress
- `knownTrustedTools`
- `knownUntrustedTools`
- `reviewCacheTtlSec`
- `trustCacheTtlSec`
- `maxContentChars`
- `antivirusMode`: `auto | disabled | required`
- `antivirusWarnUnavailable`
- `antivirusSocketPath`
- `antivirusClamdConfigPath`
- `antivirusScanTimeoutMs`

## Antivirus Integration (ClamAV)

OCS integrates with [ClamAV](https://www.clamav.net/), the open-source antivirus engine, to audit file-producing shell actions and record whether antivirus coverage was active when they ran. ClamAV provides signature-based malware detection for files introduced by agent tool calls.

What it detects:

- `git clone`
- package installs like `npm install`, `pnpm install`, `yarn install`, `bun install`
- Python package installs like `pip install` and `uv pip install`
- `cargo install`
- `go get` / `go install`
- `curl` / `wget` downloads
- archive extraction like `tar` and `unzip`

Default behavior:

- `antivirusMode = auto`
- if `clamd` is reachable and `clamonacc` is active for the target path, OCS records `Antivirus: active (on-access scanning enabled)`
- if `clamd` is reachable but on-access coverage is not configured, OCS runs a triggered scan through the `clamd` socket and records `Antivirus: active (triggered scans via clamd)`
- if no usable daemon is available, OCS records `Antivirus: unavailable - files were not scanned` and injects an antivirus warning unless `antivirusWarnUnavailable = false`

### How ClamAV integration works

1. OCS detects the [ClamAV daemon (`clamd`)](https://docs.clamav.net/manual/Usage/Scanning.html#clamd) via its Unix socket (default: `/run/clamav/clamd.ctl`)
2. When a file-producing action runs, OCS checks if [`clamonacc`](https://docs.clamav.net/manual/OnAccess.html) (on-access scanning via fanotify) is active for the target path
3. If on-access scanning is not configured, OCS falls back to triggered scans through the `clamd` socket
4. Scan verdicts (`clean`, `infected`, `unavailable`) are recorded in the antivirus ledger

### ClamAV setup for pod hosts

```bash
# Install ClamAV
sudo apt-get install -y clamav clamav-daemon

# Wait for signature database download, then start
sudo systemctl restart clamav-daemon
sudo systemctl status clamav-daemon

# Verify the socket exists
ls -la /run/clamav/clamd.ctl
```

For managed [MoltPod](https://moltpod.com/) deployments, ClamAV is pre-configured on pod hosts.

### Deliberate v1 scope

- OCS auto-detects `clamd`; it does not fall back to spawning standalone `clamscan`
- low-memory installs without a daemon should either accept the unavailable warning or disable it explicitly
- host-level fanotify / [`clamonacc`](https://docs.clamav.net/manual/OnAccess.html) remains the recommended managed-pod setup for before-access enforcement; OCS treats that as a health/coverage signal, not as a replacement for host configuration
- see the [ClamAV documentation](https://docs.clamav.net/) for full configuration reference

Antivirus state is written to:

- `~/.openclaw/plugins/openclaw-scanner/antivirus-status.json`
- `~/.openclaw/plugins/openclaw-scanner/antivirus-ledger.json`

Print the latest antivirus records with:

```bash
node scripts/print_antivirus_report.mjs --state-dir ~/.openclaw/plugins/openclaw-scanner
```

Or, on OpenClaw builds that expose plugin CLI registration:

```bash
openclaw ocs antivirus-report
openclaw ocs antivirus-report --json --limit 50
```

## Logging

The plugin emits structured log lines with an `[openclaw-scanner]` prefix for:

- ingress stubbing
- egress allow / block / approval-required decisions
- approval granted / denied / unclear decisions
- reviewed ingress outcomes
- backend failures

## Review Ledger

For ingress decisions, the plugin now saves a lightweight review ledger at:

- `~/.openclaw/plugins/openclaw-scanner/review-ledger.json`

Each record keeps:

- the source pointer: `sessionKey`, `toolCallId`, `toolName`, and transcript locator when resolvable
- `pendingKey` and `rawHash`
- the structured review response
- review token usage when the backend path exposes it, including subagent-backed gateway review

It does not persist the raw reviewed tool-result body in the ledger.

Print the latest records with:

```bash
node scripts/print_review_ledger.mjs --state-dir ~/.openclaw/plugins/openclaw-scanner
```

Or through the OpenClaw CLI when the plugin is installed:

```bash
openclaw ocs report
openclaw ocs report --json --limit 50
```

## Tests

Run:

```bash
node --test ./test/openclaw-scanner.test.mjs
```

Live pod antivirus smoke is documented in [ANTIVIRUS-SMOKE-TEST.md](./ANTIVIRUS-SMOKE-TEST.md).
