# OpenClaw Security Scanner (OCSS) Smoke Test

Last updated: 2026-03-17
Canonical spec: [OPENCLAW-SECURITY-PLUGIN-SPEC.md](./OPENCLAW-SECURITY-PLUGIN-SPEC.md)

This plugin now has a repeatable pod smoke path for the live `dev-security` messaging-profile pods.

For the ClamAV / file-scan canary on coding-profile pod hosts, use [ANTIVIRUS-SMOKE-TEST.md](./ANTIVIRUS-SMOKE-TEST.md).

## What this smoke covers

- `allow`: a benign local tool call should pass
- `ask`: a high-impact outbound action should block and request approval
- `allow once`: the exact pending action should be allowed once after a natural-language approval reply
- `deny`: a natural-language refusal should keep the action from being retried

## What this smoke does not cover on messaging-profile pods

- deterministic hard shell blocks like `rm -rf`
- browser or web ingress
- sandboxed exec

Those require a coding-profile pod with `exec` or web tools enabled.

## One-command smoke

```bash
./scripts/smoke_remote_security_plugin.sh 51.210.13.102
```

Optional session prefix:

```bash
./scripts/smoke_remote_security_plugin.sh 51.210.13.102 my-smoke
```

## How to read the results

- `allow` should return a normal assistant answer after using `sessions_list`.
- `ask` should show the `sessions_send` attempt blocked for approval.
- `allow once` may still end with a downstream `sessions.visibility=tree` error on this pod. That is acceptable for this smoke. The important evidence is:
  - the security log contains `approval_granted`
  - the security log contains `egress_allow_approved`
  - the transcript shows the tool actually executed after approval
- `deny` should end with a refusal like `I won't send it` and no follow-up tool execution.
- CLI `gateway call agent --expect-final` timeouts are not fatal for this smoke. Use the emitted transcript tails and the security log tail as the source of truth.

## Live evidence notes for this pod

The `dev-security` pod currently uses the `messaging` tool profile. The strongest live allow-once proof is a `sessions_send` request to `agent:main:main`:

- OpenClaw Security Scanner blocks it first as `ask`
- a natural-language `Yes, send it now.` grants the exact pending action once
- the tool then runs successfully on the same session via `sessions_send ... timeoutSeconds 0`
- the live transcript shows the accepted send result and the echoed inbound inter-session message

Concrete verified live prefixes on `51.210.13.102`:

- `codex-repeatable-smoke-4`
- `codex-repeatable-smoke-5`

For those prefixes, the reliable approval proof is:

- transcript shows first `sessions_send` blocked
- transcript shows user reply `Yes, send it now.`
- security log shows `approval_granted`
- security log shows `egress_allow_approved`
- transcript shows second `sessions_send` accepted

## Troubleshooting

- If `gateway call ...` returns websocket `1006`, the gateway usually was not fully ready yet after restart. Rerun after `gateway call status --json` succeeds.
- If approval review fails with `401 Unauthorized`, check whether the systemd env token and `openclaw.json` token differ. The plugin now prefers the configured gateway auth token for local HTTP review and logs a mismatch warning.
- The current pod has broken Mattermost auth. `message` tool behavior is noisy here. Prefer `sessions_send` for repeatable smoke tests on this stack.
- `allow once` can still print a CLI timeout from `gateway call agent --expect-final` even when the approved send succeeded. Treat the transcript tail and security log as source of truth.
- On current messaging pods, a natural-language denial usually works because the model chooses not to retry after `No, do not send it.` The plugin-owned denied state is still only guaranteed if the exact blocked action is attempted again later.
