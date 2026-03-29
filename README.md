# OpenClaw Scanner (OCS)

[![npm version](https://img.shields.io/npm/v/openclaw-scanner)](https://www.npmjs.com/package/openclaw-scanner)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

`openclaw-scanner` is an essential part of a broader OpenClaw security posture. It adds two checks around the model loop: on ingress, it reviews untrusted tool output through a configured review model before the next model turn; on egress, it reviews risky tool actions through a configured review model before they execute. It also records whether files and packages touched by a tool call were scanned. Today that per-call scanner coverage comes from ClamAV and OSV-Scanner.

If your agent downloads files or installs packages, we recommend running `openclaw-scand`. If it can run exec-capable or other high-impact tools, we recommend adding `openclaw-action-reviewd` too.

## Recommended Setups

| Tier | Components | Recommended for |
|------|-----------|-----------------|
| Plugin only | `openclaw-scanner` | Chat-first or otherwise low-risk profiles |
| Plugin + scan daemon | `openclaw-scanner` + `openclaw-scand` | Any profile that downloads files or installs packages |
| Plugin + scan daemon + approval service | `openclaw-scanner` + `openclaw-scand` + `openclaw-action-reviewd` | Exec-capable or other high-impact profiles |

## Quick Start

Install the plugin inside OpenClaw:

```bash
openclaw plugins install openclaw-scanner
```

If you also want the helper daemons, install the package on the host so the binaries are available to your service manager:

```bash
npm install -g openclaw-scanner
```

The npm package ships `openclaw-scand` and `openclaw-action-reviewd`. It does not create system services for them, and it does not install ClamAV or OSV-Scanner for you. Those are supplementary packages you also need.

`openclaw-scand` isolates file and package scanning. `openclaw-action-reviewd` isolates approval ownership for `ask`-level actions.

If you want help choosing a deployment tier or wiring the helper daemons into a real host, email [team@moltpod.com](mailto:team@moltpod.com).

## Mental Model

### 1. Two Guards, Two Doors

![Two Guards, Two Doors](./docs/assets/two-guards-two-doors.png)

### 2. Ingress Review For Untrusted Tool Output

![Ingress Review For Untrusted Tool Output](./docs/assets/ingress-review-flow.png)

### 3. Approval Loop For High-Impact Egress

![Approval Loop For High-Impact Egress](./docs/assets/approval-loop.png)

## Read Next

Start here:

- [Deployment](./docs/SELF-HOSTING.md) — what to install, what the helper daemons need, and when each tier makes sense
- [Configuration](./docs/CONFIGURATION.md) — default behavior, common config knobs, and example configs
- [Operations](./docs/OPERATIONS.md) — reports, ledgers, logs, and smoke-test entry points

Understand the model:

- [Architecture](./docs/ARCHITECTURE.md) — where ingress, egress, scanning, approvals, and exec posture fit together
- [Scanning](./docs/SCANNING.md) — what ClamAV and OSV-Scanner cover today, and what they do not
- [Limitations](./docs/LIMITATIONS.md) — current runtime boundaries
- [Roadmap](./docs/ROADMAP.md) — future work such as artifact taint and script re-checks

Deep reference:

- [Scanner spec](./docs/OPENCLAW-SCANNER-SPEC.md)
- [Scan daemon spec](./docs/OPENCLAW-SCAND-SPEC.md)
- [Scanner test plan](./docs/OPENCLAW-SCANNER-TEST-PLAN.md)
- [Smoke test](./docs/SMOKE-TEST.md)
- [Antivirus smoke test](./docs/ANTIVIRUS-SMOKE-TEST.md)

## Related Projects

- [OpenClaw](https://github.com/openclaw/openclaw) — the agent runtime this plugin extends
- [ClamAV](https://www.clamav.net/) — the malware scanner OCS uses for file scanning
- [OSV-Scanner](https://google.github.io/osv-scanner/) — the package vulnerability scanner OCS uses for SCA
- [bubblewrap](https://github.com/containers/bubblewrap) — the Linux sandbox `openclaw-scand` uses to isolate OSV-Scanner
- [MoltPod](https://moltpod.com/) — managed cloud hosting for OpenClaw agents
