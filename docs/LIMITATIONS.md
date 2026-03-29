# Limitations

This page is about current boundaries, not future plans.

## Hook And Runtime Limits

- OpenClaw's `before_tool_call` hook only supports `allow` or `block`
- plugin-grade `ask` therefore first appears as a block with a structured reason
- when approval stays inside the plugin, the approval loop happens on the next turn

## Approval Limits

- if you enable `openclaw-action-reviewd`, `ask` moves out of the chat turn and into a separate approval service
- once that service is enabled, the user reply in the main session is no longer the approval authority
- for exec-capable profiles, `openclaw-action-reviewd` and OpenClaw core `approvals.exec` cannot both be enabled; OCS fails startup instead of trying to run two approval authorities at once

## Exec Posture Limits

- if exec-capable tools are exposed, OCS reports `degraded_exec_posture`
- in degraded posture, ingress review, egress policy, approvals, and scanner coverage still run
- what OCS no longer credibly claims in that posture is same-UID self-tamper resistance

## Scanning Limits

- scanning is per-call, not periodic
- today scanner coverage means ClamAV plus OSV-Scanner
- OSV catches known vulnerable dependency versions; it does not catch a fresh malicious package with no advisory yet
- OCS does not have artifact provenance, script re-checking, or a persisted taint ledger yet

## Policy Limits

- routine `git push` is allowed
- `git push --force`, `git push -f`, and `git push --force-with-lease` require approval
- OCS still depends on the quality of its configured review model for gray-area decisions

For future work such as artifact taint and exec-time script re-checks, see [Roadmap](./ROADMAP.md).
