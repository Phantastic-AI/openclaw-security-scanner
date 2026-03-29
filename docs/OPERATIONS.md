# Operations

These are the commands and files you actually use when checking whether OCS is working.

## First Checks

Review decisions:

```bash
openclaw ocs report
openclaw ocs report --json --limit 50
```

Antivirus coverage:

```bash
openclaw ocs antivirus-report
openclaw ocs antivirus-report --json --limit 50
```

Package vulnerability coverage:

```bash
openclaw ocs sca-report
openclaw ocs sca-report --json --limit 50
```

Exec posture:

```bash
openclaw ocs posture-report
openclaw ocs posture-report --json
```

The helper scripts are still available if you need them:

```bash
node scripts/print_review_ledger.mjs --state-dir ~/.openclaw/plugins/openclaw-scanner
node scripts/print_antivirus_report.mjs --state-dir ~/.openclaw/plugins/openclaw-scanner
```

## Persistent State

Review ledger:

- `~/.openclaw/plugins/openclaw-scanner/review-ledger.json`

Antivirus:

- `~/.openclaw/plugins/openclaw-scanner/antivirus-status.json`
- `~/.openclaw/plugins/openclaw-scanner/antivirus-ledger.json`

Package scanning:

- `~/.openclaw/plugins/openclaw-scanner/sca-status.json`
- `~/.openclaw/plugins/openclaw-scanner/sca-ledger.json`

Exec posture:

- `~/.openclaw/plugins/openclaw-scanner/posture-status.json`

## Logs

The plugin emits structured log lines with an `[openclaw-scanner]` prefix for:

- ingress stubbing and quarantine
- egress allow, block, and approval-required decisions
- approval granted, denied, and unclear outcomes
- scanner backend failures
- daemon availability problems

## Source Of Truth When Signals Disagree

When a fail-closed scan or approval path blocks a real side effect, the assistant can still guess what would have happened. In those cases, trust these in this order:

1. actual workspace mutation
2. OCS ledgers and status files
3. `openclaw-scand` or `openclaw-action-reviewd` logs
4. the assistant reply

That matters most for blocked exec and package-install actions.

## Tests And Smokes

Local test suite:

```bash
npm test
```

Live QA docs:

- [Smoke test](./SMOKE-TEST.md) — live pod messaging and scan-daemon smoke
- [Antivirus smoke test](./ANTIVIRUS-SMOKE-TEST.md) — exec-capable canary scan smoke
- [Scanner test plan](./OPENCLAW-SCANNER-TEST-PLAN.md) — broader QA matrix
