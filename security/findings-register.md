# Findings Register — DevSecOps Pipeline

Security findings the pipeline surfaces on the **`vulnerable`** branch, each mapped
to the OWASP Top 10 (2021), the scanner that catches it, and its remediation
status on **`main`**. This is the register a reviewer reads to see that the gates
actually work and that every issue was driven to closed.

## Summary

| Severity | Count | Status on `main` |
|----------|-------|------------------|
| Critical | 3 | Fixed |
| High | 4 | Fixed |
| Medium | 3 | Fixed |
| **Total** | **10** | **All fixed** |

## Register

| ID | Finding | OWASP | Caught by | Severity | Status |
|----|---------|-------|-----------|----------|--------|
| DSO-01 | SQL injection in `/login` (string-built query) | A03 Injection | Semgrep (`sql-string-format`) + ZAP 40018 | Critical | Fixed |
| DSO-02 | SQL injection in `/search` | A03 Injection | Semgrep + ZAP 40018 | Critical | Fixed |
| DSO-03 | OS command injection in `/ping` | A03 Injection | Semgrep (`os-command-from-request`) + ZAP 90020 | Critical | Fixed |
| DSO-04 | IDOR / broken access control on `/users/<id>` | A01 | Semgrep (authz test) + manual/ZAP | High | Fixed |
| DSO-05 | SSRF in `/fetch` (no allowlist) | A10 | Semgrep (`requests-get-unvalidated-url`) | High | Fixed |
| DSO-06 | JWT signed with hardcoded secret, no expiry | A07 | Semgrep + Gitleaks | High | Fixed |
| DSO-07 | MD5 password hashing | A02 | Semgrep (`md5-for-passwords`) | High | Fixed |
| DSO-08 | Hardcoded secrets in source + committed `.env` | A02/A05 | Gitleaks | Medium | Fixed |
| DSO-09 | Vulnerable dependencies (Flask 0.12.2, PyYAML 3.13, urllib3 1.24.1, …) | A06 | Trivy SCA | Medium | Fixed |
| DSO-10 | Insecure container (root user, `latest` base, baked secret) + Flask `debug=True` | A05 | Trivy config + Semgrep (`flask-debug-true`) | Medium | Fixed |

## How each gate contributes

| Gate | Tool | What it caught |
|------|------|----------------|
| SAST | Semgrep | DSO-01/02/03/05/06/07/10 (code-level flaws) |
| Secrets | Gitleaks | DSO-06/08 (committed secrets) |
| SCA | Trivy (fs) | DSO-09 (vulnerable dependencies) |
| Container | Trivy (image + config) | DSO-10 (Dockerfile misconfig, image CVEs) |
| DAST | OWASP ZAP | DSO-01/02/03 confirmed at runtime |

## Reading this honestly

The vulnerable app is a deliberate teaching target (like DVWA / OWASP Juice
Shop). The value isn't "look, bugs" — it's the closed loop: **each finding is
caught by a specific automated gate, mapped to OWASP, and remediated on `main`
with a regression test that keeps it fixed.** The before/after is in
[`remediation.md`](remediation.md).
