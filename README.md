# DevSecOps Pipeline

[![security](https://github.com/Rancho-1001/devsecops-pipeline/actions/workflows/security.yml/badge.svg)](https://github.com/Rancho-1001/devsecops-pipeline/actions/workflows/security.yml)
[![SAST: Semgrep](https://img.shields.io/badge/SAST-Semgrep-1f6feb)](.semgrep/)
[![SCA/Container: Trivy](https://img.shields.io/badge/SCA%20%2B%20Container-Trivy-1904da)](.github/workflows/security.yml)
[![Secrets: Gitleaks](https://img.shields.io/badge/Secrets-Gitleaks-ff2e63)](.gitleaks.toml)
[![DAST: OWASP ZAP](https://img.shields.io/badge/DAST-OWASP%20ZAP-00549e)](.zap/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> A CI/CD security pipeline with **build-failing gates** wrapped around a
> deliberately vulnerable Flask API. SAST (Semgrep), dependency + container
> scanning (Trivy), secret scanning (Gitleaks), and DAST (OWASP ZAP) all run in
> GitHub Actions. The `vulnerable` branch trips every gate; `main` is the
> remediated app where they all pass. The remediation is a reviewable diff with
> regression tests.
>
> **The vulnerable app is a deliberate teaching target (like DVWA / OWASP Juice
> Shop), for scanning only. This repo contains no offensive tooling — just the
> target, the scanners, and the fixes. Self-directed lab work.**

---

## Why this project exists

I'm a CS grad (SWE + AWS internship, Security+ SY0-701) moving into cloud
security / DevSecOps. This shows I can shift security left: encode security as
code, gate a pipeline on it, and drive real findings to closed with tests that
keep them closed — not just run a scanner once.

## The security gates

| Gate | Tool | Scope | Fails build when… |
|------|------|-------|-------------------|
| SAST | **Semgrep** | source code (registry packs + custom rules) | any rule matches (`--error`) |
| Secrets | **Gitleaks** | full git history | a secret is committed |
| SCA | **Trivy fs** | `requirements.txt` | High/Critical dependency CVE |
| Container | **Trivy image + config** | Docker image & Dockerfile | High/Critical CVE or misconfig |
| DAST | **OWASP ZAP** | the running API | a FAIL-level runtime alert |
| Tests | **pytest** | app + security regression tests | any test fails |

Pipeline: [`.github/workflows/security.yml`](.github/workflows/security.yml).

## What the gates catch (10 findings, OWASP-mapped)

| ID | Finding | OWASP | Gate |
|----|---------|-------|------|
| DSO-01/02 | SQL injection (`/login`, `/search`) | A03 | Semgrep + ZAP |
| DSO-03 | OS command injection (`/ping`) | A03 | Semgrep + ZAP |
| DSO-04 | IDOR / broken access control | A01 | tests + ZAP |
| DSO-05 | SSRF (`/fetch`) | A10 | Semgrep |
| DSO-06 | Weak JWT (hardcoded key, no expiry) | A07 | Semgrep + Gitleaks |
| DSO-07 | MD5 password hashing | A02 | Semgrep |
| DSO-08 | Hardcoded secrets / committed `.env` | A02/A05 | Gitleaks |
| DSO-09 | Vulnerable dependencies | A06 | Trivy SCA |
| DSO-10 | Insecure container + Flask debug | A05 | Trivy config + Semgrep |

Details + before/after: [`security/findings-register.md`](security/findings-register.md)
· [`security/remediation.md`](security/remediation.md).

## The red → green story

```
vulnerable branch  ──►  CI security gates RED  (10 OWASP findings)
        │
        ▼   fix each finding on main + add regression tests
main branch        ──►  CI security gates GREEN
```

`main` holds the **fixed** app (`app/`). The intentionally-vulnerable code
(`vulnerable-app/`) is kept alongside so you can diff it directly; a script
overlays it onto `app/` to build the `vulnerable` branch that makes the gates go
red:

```bash
bash scripts/create-vulnerable-branch.sh
git push -u origin vulnerable          # watch the Actions run go red
git diff vulnerable main -- app        # the remediation diff
```

## Try it locally (no CI needed)

```bash
# Fixed app — expect clean + tests pass
bash scripts/run-local-scans.sh app

# Vulnerable app — expect findings from every applicable scanner
bash scripts/run-local-scans.sh vulnerable-app
```

(Install `semgrep`, `gitleaks`, `trivy` first — see [`SETUP.md`](SETUP.md).)

## Repository layout

```
devsecops-pipeline/
├── app/                 # FIXED Flask API (main; gates pass) + security tests
├── vulnerable-app/      # intentionally vulnerable version (diff/overlay source)
├── .github/workflows/   # security.yml — the gated pipeline
├── .semgrep/            # custom SAST rules (OWASP-tagged)
├── .gitleaks.toml       # secret-scan config
├── .zap/                # ZAP baseline rule tuning
├── docker-compose.dast.yml  # brings up the API for DAST
├── security/            # findings register + remediation before/after
└── scripts/             # create-vulnerable-branch, run-local-scans
```

## Design choices worth defending

- **Security as code, gated.** Every check is a build-failing gate, not an
  advisory report — a vulnerable change can't merge.
- **Defense in depth across the SDLC.** SAST (code) + SCA (deps) + secrets +
  container + DAST (runtime) catch different classes; several findings are caught
  by more than one gate.
- **Fixes are pinned by tests.** `app/tests/test_security.py` asserts the app
  *behaves* securely (SQLi doesn't bypass auth, IDOR returns 403, SSRF to the
  metadata IP is blocked), so a regression fails CI.
- **Custom Semgrep rules, OWASP-mapped.** Not just registry packs — targeted
  rules for the exact anti-patterns, each tagged with its OWASP/CWE id.

## Safety & ethics

The vulnerable app is a scanning target only; never deploy it anywhere reachable.
No exploit or attack code is included. This is self-directed lab work.

## Roadmap

- Add SBOM generation (Trivy/Syft) + provenance attestation.
- Gate on Semgrep SARIF severity thresholds and open PRs with autofixes.
- Add IaC scanning (Checkov/tfsec) to tie into the AWS Cloud Security Lab.

---

*Part of a four-project cybersecurity portfolio: (1) AWS Cloud Security Lab ·
(2) SOC / Threat Detection Lab · (3) DevSecOps Pipeline · (4) Vulnerability
Management Lab.*
