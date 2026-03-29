# Configuration

Most installs only touch a small part of the config surface. Start with the defaults, then change only the parts that match the deployment tier you actually run.

## Minimal Config

If you are using the normal OpenClaw gateway-backed review path, the smallest useful config is:

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

That relies on these defaults:

- `ingressBackend = "gateway"` unless both `apiUrl` and `apiKey` are set, in which case ingress defaults to `promptscanner`
- `egressBackend = "gateway"`
- `trustBackend = "gateway"`
- `gatewayReviewTransport = "auto"`
- `trustModel`, `ingressModel`, and `egressModel` inherit the pod's primary agent model
- `approvalIntentModel` defaults to `egressModel`, then the pod's primary model
- `approvalTtlSec = 900` (15 minutes)
- `trustCacheTtlSec = 2592000` (30 days)
- `reviewCacheTtlSec = 604800` (7 days)
- `maxContentChars = 24000`

## Choose Review Backends

### Default gateway-backed review

This is the normal path:

- `ingressBackend = "gateway"`
- `egressBackend = "gateway"`
- `trustBackend = "gateway"`

`gatewayReviewTransport = "auto"` prefers internal subagent review and only uses HTTP review when the gateway is on loopback, token-authenticated, and has an explicit review-capable HTTP endpoint enabled.

Important:

- if you set both `apiUrl` and `apiKey`, ingress review defaults to `promptscanner` even if you do not set `ingressBackend` explicitly
- if you do not want that automatic switch, set `ingressBackend = "gateway"` directly

### Optional external ingress scanning

If you already operate an external prompt-scanning API, you can send ingress review there:

```json
{
  "plugins": {
    "entries": {
      "openclaw-scanner": {
        "enabled": true,
        "config": {
          "ingressBackend": "promptscanner",
          "apiUrl": "https://scanner.example.com",
          "apiKey": "${PROMPTSCANNER_API_KEY}",
          "callerId": "pod-a-openclaw",
          "podId": "pod-a"
        }
      }
    }
  }
}
```

`promptscanner` is just the backend hook name. It does not require any specific product.

## Scan Controls

These settings matter when you care about file and package scanning:

### Antivirus

- `antivirusMode = "auto" | "required" | "disabled"`
- `antivirusSocketPath`
- `antivirusClamdConfigPath`
- `antivirusWarnUnavailable`
- `antivirusScanTimeoutMs`

Use `required` if file-producing actions must fail closed when antivirus coverage is unavailable.

### Package vulnerability scanning

- `scaMode = "auto" | "required" | "disabled"`
- `osvScannerPath`
- `scaWarnUnavailable`
- `scaWarnDetected`
- `scaWarnInconclusive`
- `scaScanTimeoutMs`

Use `required` if package installs must fail closed when OSV-Scanner is unavailable.

### Separate scan daemon

- `scanBrokerMode = "auto" | "required" | "disabled"`
- `scanBrokerSocketPath`

Use this when you want `openclaw-scand` to own ClamAV and OSV-Scanner execution outside the main OpenClaw UID.

## Approval Controls

These settings matter when you care about `ask` decisions and approval ownership:

- `approvalIntentModel`
- `approvalTtlSec`
- `actionReviewMode = "auto" | "required" | "disabled"`
- `actionReviewSocketPath`

Use `actionReviewMode` when you want `openclaw-action-reviewd` to own approvals outside the main OpenClaw process.

Important:

- `headlessAskPolicy` is currently fixed to `block`
- if `actionReviewMode` is enabled for an exec-capable profile, OpenClaw core `approvals.exec` forwarding must be off on that same profile

## Trust Hints And Tuning

These are the knobs most operators touch after the basic setup:

- `knownTrustedTools`
- `knownUntrustedTools`
- `trustModel`
- `ingressModel`
- `egressModel`
- `reviewCacheTtlSec`
- `trustCacheTtlSec`
- `maxContentChars`

Use the tool lists sparingly. They are hints layered on top of the built-in trust heuristics, not a replacement for review.

## Less-Common Fields

Most installs can ignore these unless they are integrating OCS into a larger environment:

- `gatewayBaseUrl`
- `gatewayToken`
- `policyVersion`
- `mainModel`

## Current Fixed Behavior

These are part of current behavior, not useful knobs to tune:

- `warnMode` is currently fixed to `wrap`
- `persistMode` is currently fixed to `stub`
- `headlessAskPolicy` is currently fixed to `block`

## Hardened Example

This is the shape of a hardened deployment that uses both helper daemons:

```json
{
  "plugins": {
    "entries": {
      "openclaw-scanner": {
        "enabled": true,
        "config": {
          "scanBrokerMode": "required",
          "scanBrokerSocketPath": "/run/openclaw-scand/ocs.sock",
          "actionReviewMode": "required",
          "actionReviewSocketPath": "/run/openclaw-action-reviewd/ocs.sock",
          "antivirusMode": "required",
          "scaMode": "required"
        }
      }
    }
  }
}
```
