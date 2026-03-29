# Scanning

OCS does not run a background scanner. It records scan coverage on the tool call that created, downloaded, extracted, or installed the files in question.

Today there are two scanner families:

| Scanner | What it covers | What it tells you |
|---------|----------------|-------------------|
| ClamAV | downloaded files, extracted archives, package-install side effects, other file-producing shell actions | whether malware scanning was active and what verdict it returned |
| OSV-Scanner | JavaScript and Python package installs | whether known vulnerable dependency versions were detected |

## When OCS Scans

The current coverage triggers include:

- `git clone`
- `curl` and `wget` downloads
- archive extraction such as `tar` and `unzip`
- package installs such as `npm`, `pnpm`, `yarn`, `bun`, `pip`, and `uv pip`
- other shell actions that create or populate directories OCS can identify

That coverage is per-call. It is not a periodic host scanner.

## ClamAV

OCS integrates with [ClamAV](https://www.clamav.net/) through `clamd`.

Default behavior:

- `antivirusMode = "auto"`
- if `clamd` is reachable and `clamonacc` is active for the target path, OCS records `Antivirus: active (on-access scanning enabled)`
- if `clamd` is reachable but on-access coverage is not configured, OCS runs a triggered scan through the `clamd` socket and records `Antivirus: active (triggered scans via clamd)`
- if no usable daemon is available, OCS records `Antivirus: unavailable - files were not scanned` and can inject an inline warning

Deliberate scope:

- OCS uses `clamd`; it does not fall back to standalone `clamscan`
- `clamonacc` is treated as a coverage signal, not as something OCS configures for you
- low-memory hosts without a running daemon should either accept the unavailable warning or disable it explicitly

## OSV-Scanner

OCS runs [OSV-Scanner](https://google.github.io/osv-scanner/) after JavaScript and Python package installs.

Default behavior:

- `scaMode = "auto"`
- OCS invokes `osv-scanner scan source -r <install-root> --format json`
- verdicts are recorded as `clean`, `advisory`, `inconclusive`, or `unavailable`
- `required` mode blocks package-install actions if OSV-Scanner is unavailable

Important limits:

- OSV source scanning depends on supported manifests and lockfiles
- `inconclusive` does not mean clean
- OSV catches known vulnerable dependency versions, not a brand-new malicious package with no advisory yet

## What `openclaw-scand` Changes

When `openclaw-scand` is enabled:

- ClamAV and OSV-Scanner execution move out of the main OpenClaw UID
- scan requests cross a Unix socket boundary
- OSV-Scanner runs inside `bubblewrap`
- `required` mode fails closed when the daemon is unavailable

When `openclaw-scand` is disabled:

- OCS runs the scanners locally in the main OpenClaw context

`openclaw-scand` does not install ClamAV or OSV-Scanner for you. See [Deployment](./SELF-HOSTING.md) for host setup.

## What Scanning Does Not Mean

Scanning is useful, but narrow:

- it does not mean a file or package is generally safe
- it does not replace ingress review or egress policy
- it does not give you artifact provenance or script re-checking yet
- it does not prove the host is periodically or continuously scanned
