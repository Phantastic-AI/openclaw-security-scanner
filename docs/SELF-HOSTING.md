# Deployment

This guide is for operators running OCS outside managed MoltPod automation.

## Choose A Tier

| Tier | What you run | Use it when |
|------|--------------|-------------|
| Plugin only | `openclaw-scanner` | Your profiles are chat-first or otherwise low-risk |
| Plugin + scan daemon | `openclaw-scanner` + `openclaw-scand` | Your agent downloads files or installs packages |
| Plugin + scan daemon + approval service | `openclaw-scanner` + `openclaw-scand` + `openclaw-action-reviewd` | Your agent has exec-capable or other high-impact tools |

The first tier is valid. The second and third tiers are what we recommend for any serious tool-using deployment.

## What To Install

Every setup starts with the plugin inside OpenClaw:

```bash
openclaw plugins install openclaw-scanner
```

If you want `openclaw-scand` or `openclaw-action-reviewd`, install the package on the host as well so those binaries are available to your service manager:

```bash
npm install -g openclaw-scanner
```

### Supplementary packages you also need

`openclaw-scand` orchestrates two scanners. It does not bundle or install them:

- **ClamAV / `clamd`** for malware scanning
- **OSV-Scanner** for package vulnerability scanning

On Debian or Ubuntu, a practical starting point is:

```bash
sudo apt-get update
sudo apt-get install -y clamav clamav-daemon
sudo systemctl enable --now clamav-daemon

go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest
sudo install -m 0755 "$HOME/go/bin/osv-scanner" /usr/local/bin/osv-scanner
```

If either backend is missing:

- coverage becomes unavailable or degraded
- `required` mode fails closed for covered actions
- `auto` mode falls back with a warning

## Tier 1: Plugin Only

Use this when you want ingress review and egress policy, but you are not yet isolating scanning or approvals into separate services.

Typical config:

```json
{
  "plugins": {
    "entries": {
      "openclaw-scanner": {
        "enabled": true
      }
    }
  }
}
```

## Tier 2: Add `openclaw-scand`

Use this when your agent downloads files or installs packages.

What `openclaw-scand` needs:

- its own service user
- a long-running service under `systemd` or equivalent
- a Unix socket, by default `/run/openclaw-scand/ocs.sock`
- access to `clamd`
- `osv-scanner` on the host

What to configure in OCS:

- `scanBrokerMode`
- `scanBrokerSocketPath`

Recommended settings:

- use `scanBrokerMode = "required"` when scan-covered actions must fail closed if the daemon is unavailable
- use `scanBrokerMode = "auto"` only if you explicitly want degraded local fallback behavior

Minimal service shape:

```ini
[Unit]
Description=OpenClaw scan daemon
After=network-online.target

[Service]
User=openclaw-scand
Group=openclaw-scand
RuntimeDirectory=openclaw-scand
ExecStart=/usr/local/bin/openclaw-scand
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Important socket note:

- the socket directory and socket file must be reachable by the OpenClaw runtime user, either through a shared group or an explicit ACL
- `openclaw-scand` creates the socket path, but it does not manage your host's permission model for you

## Tier 3: Add `openclaw-action-reviewd`

Use this when `ask` decisions should be owned outside the main OpenClaw process, especially on exec-capable profiles.

What `openclaw-action-reviewd` needs:

- its own service user
- a long-running service under `systemd` or equivalent
- a Unix socket, by default `/run/openclaw-action-reviewd/ocs.sock`
- reviewer transport credentials
- gateway access so it can correlate reviewer replies with pending approvals

What to configure in OCS:

- `actionReviewMode`
- `actionReviewSocketPath`

Recommended settings:

- use `actionReviewMode = "required"` when approval service availability is part of the security boundary
- use `actionReviewMode = "auto"` only if you are willing to fall back to the plugin's in-process approval loop

Minimal service shape:

```ini
[Unit]
Description=OpenClaw action review service
After=network-online.target

[Service]
User=openclaw-action-reviewd
Group=openclaw-action-reviewd
RuntimeDirectory=openclaw-action-reviewd
EnvironmentFile=/etc/default/openclaw-action-reviewd
ExecStart=/usr/local/bin/openclaw-action-reviewd
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

The environment file is where you supply the review transport credentials, reviewer identities, and gateway connection details.

Transport-specific settings are intentionally deeper than this guide. Use the daemon help and deep reference docs when wiring the current built-in transport.

Important:

- for exec-capable profiles, `openclaw-action-reviewd` must be the only approval authority
- if OpenClaw core `approvals.exec` forwarding is also enabled on the same profile, OCS fails startup with a config error

## Deployment Checklist

- plugin installed in OpenClaw
- helper binaries installed on the host if you are using them
- ClamAV and OSV-Scanner installed when `openclaw-scand` is enabled
- helper daemons running under separate UIDs
- Unix sockets reachable at the configured paths
- OCS modes set to `required` or `auto` deliberately, not by accident

If you want help choosing a tier or wiring the services into a real host, email [team@moltpod.com](mailto:team@moltpod.com).
