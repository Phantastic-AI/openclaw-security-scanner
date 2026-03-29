# Roadmap

This page is future work, not current release behavior.

## Artifact Taint And Script Re-checks

The next major policy gap is write-then-exec behavior.

What we want:

- keep session taint in memory for ingress
- add a persisted artifact ledger for files, scripts, downloads, archives, and package trees
- key artifact state by canonical path plus content hash
- track per-backend results such as malware scanning, package scanning, and future script review
- re-check script contents at execution time, not just when the file was first written

Why:

- write-time inspection is useful but not final because the file can change later
- `bash script.sh` or `python script.py` should be judged on the final bytes that will run
- a previous clean result must become stale when the content changes

## Proposed Storage Model

- session taint stays in OCS memory
- artifact taint moves toward a daemon-owned ledger under `openclaw-scand`
- xattrs, fanotify, IMA, fs-verity, and LSM labels are useful helpers later, but not the source of truth by themselves

## Proposed Future Exec-Time Behavior

- detect script-like launchers
- re-read and re-hash the final file contents
- hard malicious or protected-data exfil patterns would `block`
- ordinary offsite send of non-secret data would `ask`
- benign local automation would `allow` or `review`

## Important Fallback Rule

- if exec-time script review is too large, too expensive, or incomplete, OCS must not silently treat it as clean
- deterministic rules still run first
- incomplete high-risk review should degrade to at least `ask`
- required review that cannot run for a high-risk launcher should `block`

## Broader Scanner Coverage

Today OCS scanner coverage is ClamAV plus OSV-Scanner. We expect to broaden that surface over time, especially around:

- executable payloads
- script content and launcher patterns
- package-policy checks beyond known-vulnerability lookups
