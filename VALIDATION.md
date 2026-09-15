# Validation performed

## CyberForge feature merge — September 15, 2026

Imported the user's landing page, dashboard, redesigned missions, local runner, and preview artifacts. Retained the real Ubuntu provisioning script. Browser checks cover all 15 mission cards, three views, legacy progress migration, persisted reset, wrong/correct answers, navigation while verification is pending, numeric target-host replacement, HTTP clipboard copying, health indicators, and mobile layouts. Python tests also check preview asset serving and that the local runner does not impersonate SSH. The bundled sample audit record is not presented as a real event from the local host.

The complete Ubuntu/Kali deployment acceptance below remains outstanding; this UI merge does not claim to complete it.

## Original implementation

Validated on 2026-09-10 from the Windows development workspace.

| Check | Result |
|---|---|
| Python tests | 35 passed: every answer, wrong answers, malformed bodies, type/length limits, Burp tampering, public metadata, health status, source-path protection, and embedded protocol handlers |
| Bash syntax | `bash -n setup_vulnerabilities.sh` passed |
| Browser interactions | Passed in headless Edge: all 15 lessons, hint toggles, incorrect/correct submission, persisted progress after reload, and dynamic numeric target-host replacement |
| Clipboard | HTTP-origin fallback returned success in browser test |
| Responsive layout | Desktop 1440 px and mobile 390 px screenshots inspected; no mobile document overflow |
| ext4 artifact smoke test | Linux e2fsprogs 1.47.3 created the exact 2 MiB format, wrote and deleted the note, reported its block free, and retained the expected token |

The local Linux environment did not have `blkls`; its smoke test therefore verified deleted-block retention directly with debugfs and a raw block read. The Ubuntu installer includes an actual `blkls` recovery assertion and refuses to finish artifact generation if it fails.

The embedded Ncat protocol handlers were tested through their actual stdin/stdout interface. These checks do not establish live Ncat socket behavior on Ubuntu. Docker's engine was unavailable, and no booted Ubuntu/Kali VM pair was available for a complete provisioning run.

**Still required before a verified lab release:** run provisioning on Ubuntu 24.04; confirm live Ncat protocols, SSH password login, auditd kernel event export, OpenSSL decryption, Snort/YARA detection, and actual Sleuth Kit recovery using the student commands; complete all 15 lessons from Kali; reboot Ubuntu and recheck the services; repeat with Internet access disconnected. No claim of completed VM acceptance or public-production readiness is made.

Browser screenshots are generated under `test-results/`. The developer preview on `127.0.0.1:5050` has the UI/API only, so a Partial service indicator there is expected.
