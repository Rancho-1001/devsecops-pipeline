#!/usr/bin/env bash
#
# Run the same security gates locally that CI runs. Point it at a directory
# (default: app). Requires: semgrep, gitleaks, trivy on PATH (see SETUP.md).
#
#   bash scripts/run-local-scans.sh            # scan the fixed app (expect clean)
#   bash scripts/run-local-scans.sh vulnerable-app   # scan the vulnerable app (expect findings)
set -uo pipefail

TARGET="${1:-app}"
echo "== Scanning: $TARGET =="
rc=0

echo -e "\n--- Semgrep (SAST) ---"
if command -v semgrep >/dev/null; then
  semgrep scan --config p/python --config p/flask --config p/security-audit \
    --config .semgrep/custom-rules.yml --error "$TARGET" || rc=1
else
  echo "semgrep not installed (pip install semgrep)"; fi

echo -e "\n--- Gitleaks (secrets) ---"
if command -v gitleaks >/dev/null; then
  gitleaks detect --source "$TARGET" --config .gitleaks.toml --no-git -v || rc=1
else
  echo "gitleaks not installed"; fi

echo -e "\n--- Trivy (dependencies) ---"
if command -v trivy >/dev/null; then
  trivy fs --scanners vuln --severity HIGH,CRITICAL --exit-code 1 "$TARGET" || rc=1
else
  echo "trivy not installed"; fi

echo -e "\n--- pytest (security regression tests) ---"
if [ "$TARGET" = "app" ] && command -v pytest >/dev/null; then
  JWT_SECRET=test-secret-not-for-prod pytest -q app/tests || rc=1
fi

echo -e "\n== Done. Overall exit: $rc (0 = clean, 1 = findings) =="
exit $rc
