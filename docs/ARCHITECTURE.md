# Architecture

This doc explains who decides what, where the helper daemons sit, and which trust boundaries actually improve when you turn them on.

If you already read the README, the new material starts at [Who Decides What](#who-decides-what). The diagrams are repeated here on purpose so this page still stands on its own.

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

## Who Decides What

| Component | What it decides | What it does not decide |
|-----------|-----------------|-------------------------|
| `openclaw-scanner` | Whether ingress content is allowed, warned, or quarantined; whether risky egress is allowed, asked, or blocked | It does not provide OS isolation by itself |
| Configured review model | Gray-area ingress and egress verdicts when deterministic rules are not enough | It does not own final approval state once `openclaw-action-reviewd` is enabled |
| `openclaw-scand` | Runs ClamAV and OSV-Scanner outside the main OpenClaw UID | It does not decide whether a tool action is safe |
| `openclaw-action-reviewd` | Owns pending approval requests and one-shot approve/deny outcomes | It does not classify an action as safe or unsafe in the first place |

The important boundary is this: OCS decides whether an action is `allow`, `ask`, or `block`. `openclaw-action-reviewd` only owns the approval step for `ask`.

## Review Backends

By default, OCS uses the review models already configured in OpenClaw.

- ingress review runs before the next model turn
- egress review runs before risky tool calls execute
- approval-intent review can use a separate configured model when approval stays inside the plugin

The `promptscanner` backend is just a generic hook for an external prompt-scanning API. OCS does not require any specific product behind that name.

Gateway review prefers an internal subagent transport. It only falls back to gateway HTTP review when the gateway is on loopback, token-authenticated, and has an explicit review-capable HTTP endpoint enabled.

## Scan Isolation

`openclaw-scand` moves malware scanning and package scanning out of the main OpenClaw UID.

What improves:

- scan execution crosses a Unix socket boundary
- ClamAV and OSV-Scanner no longer run inside the main OpenClaw user
- OSV-Scanner runs inside `bubblewrap`

What does not improve:

- approval integrity
- the integrity of the rest of the OpenClaw process

## Approval Isolation

`openclaw-action-reviewd` moves `ask` ownership out of the main OpenClaw process.

What it owns:

- pending action requests
- reviewer-transport polling
- free-text reviewer intent classification
- one-shot approval grants
- denial and unclear outcomes

For exec-capable profiles, it must be the only approval authority. If OpenClaw core `approvals.exec` forwarding is also enabled on the same profile, OCS now fails startup with a config error.

## Exec Posture

OCS tracks two posture states:

- `normal`
- `degraded_exec_posture`

`degraded_exec_posture` means exec-capable tools are configured or observed. This is an honesty feature, not a panic switch. In degraded posture, ingress review, egress policy, approvals, ClamAV scanning, and OSV-Scanner checks still run. What OCS stops claiming is same-UID self-tamper resistance.

What changes in degraded posture:

- OCS emits a startup warning
- OCS persists posture to `~/.openclaw/plugins/openclaw-scanner/posture-status.json`
- `openclaw ocs posture-report` exposes the current state
- OCS still blocks tool-mediated access to its own control-plane paths:
  - `~/.openclaw/openclaw.json`
  - `~/.openclaw/plugins/openclaw-scanner/**`

## Hardening Order

The current hardening order is simple:

1. OCS inside the OpenClaw hook boundary
2. `openclaw-scand` for a separate-UID scan boundary
3. `openclaw-action-reviewd` for a separate-UID approval boundary

That third step is where approval integrity starts to mean something under exec-capable profiles.
