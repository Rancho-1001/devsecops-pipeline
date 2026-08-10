# SETUP — Run the Pipeline, the Scanners, and the Red→Green Flow

## 0. Prerequisites

| Tool | Install | Used for |
|------|---------|----------|
| Python 3.12 | python.org / pyenv | run the API + tests |
| Docker | docker.com | build image, DAST via compose |
| Semgrep | `pip install semgrep` | local SAST |
| Gitleaks | `brew install gitleaks` / [releases](https://github.com/gitleaks/gitleaks/releases) | local secret scan |
| Trivy | `brew install trivy` / [install](https://aquasecurity.github.io/trivy/) | local SCA + container scan |

The CI pipeline needs none of these installed locally — it runs everything in
GitHub Actions. Local tools are only for reproducing the gates on your machine.

---

## 1. Run the fixed API locally

```bash
cd app
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export JWT_SECRET=$(python -c "import secrets;print(secrets.token_urlsafe(32))")
python seed.py
python app.py            # serves on http://127.0.0.1:5000

# in another shell:
curl -s -XPOST localhost:5000/login -H 'content-type: application/json' \
  -d '{"username":"alice","password":"password1"}'
```

Run the security regression tests:

```bash
JWT_SECRET=test-secret-not-for-prod pytest -q app/tests
```

---

## 2. Reproduce the gates locally

```bash
# From the repo root:
bash scripts/run-local-scans.sh app             # fixed app  -> clean
bash scripts/run-local-scans.sh vulnerable-app  # vuln app   -> findings
```

Or run a single scanner:

```bash
semgrep scan --config p/python --config p/flask --config p/security-audit \
             --config .semgrep/custom-rules.yml --error vulnerable-app
gitleaks detect --source vulnerable-app --config .gitleaks.toml --no-git -v
trivy fs --scanners vuln --severity HIGH,CRITICAL --exit-code 1 vulnerable-app
```

---

## 3. Run DAST (OWASP ZAP) locally

```bash
docker compose -f docker-compose.dast.yml up --build -d
# Baseline scan via the official ZAP image:
docker run --rm --network host -v "$(pwd)/.zap:/zap/wrk" \
  ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
  -t http://localhost:5000 -r zap-report.html -c rules.tsv
docker compose -f docker-compose.dast.yml down
```

---

## 4. Wire up CI

Push the repo to GitHub. The workflow runs on push/PR to `main` and `vulnerable`.

- **Semgrep SARIF** appears under the repo's **Security → Code scanning** tab.
- Each job is a required gate; a failing gate fails the run.

For the Gitleaks Action on organization repos you may need a
`GITLEAKS_LICENSE` secret (free for personal/public repos).

---

## 5. Demonstrate red → green

```bash
# On a clean main:
bash scripts/create-vulnerable-branch.sh
git push -u origin vulnerable
```

- The `vulnerable` branch's Actions run goes **red** — each gate reports its
  findings (Semgrep SAST, Gitleaks secrets, Trivy CVEs, ZAP runtime).
- `main` stays **green**.
- View the fix: `git diff vulnerable main -- app`, or read
  [`security/remediation.md`](security/remediation.md).

To present it as a pull request, branch off `vulnerable`, apply the fixes (or
merge `main`'s `app/`), and open a PR — the checks flip from red to green on the
PR, which is the artifact to screenshot for your portfolio.

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `KeyError: 'JWT_SECRET'` on startup | Export `JWT_SECRET` — the app fails closed by design |
| Semgrep finds issues in `app/` | It shouldn't; ensure you didn't overlay the vulnerable code onto `main` |
| Gitleaks flags `main` | Confirm `.gitleaks.toml` allowlists `vulnerable-app/`; real secrets belong only in a gitignored `.env` |
| Trivy image scan slow | First run pulls the DB; subsequent runs are cached |
| ZAP finds nothing on fixed app | Expected — baseline should pass; it lights up on the `vulnerable` branch |
