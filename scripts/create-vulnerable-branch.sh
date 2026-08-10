#!/usr/bin/env bash
#
# Creates the `vulnerable` branch used to demonstrate the security gates going
# red. It overlays the intentionally-vulnerable code (vulnerable-app/) onto the
# scanned path (app/) and commits, so pushing this branch makes CI catch all 10
# planted OWASP findings. `main` stays green.
#
# Usage:
#   bash scripts/create-vulnerable-branch.sh
#   git push -u origin vulnerable
# Then open a PR from a fresh remediation branch back to main, or simply compare
# branches to view the red -> green remediation diff.
set -euo pipefail

if [ -n "$(git status --porcelain)" ]; then
  echo "Working tree not clean. Commit or stash first." >&2
  exit 1
fi

git switch -c vulnerable

# Replace the deployed app with the vulnerable version (same paths, bad code).
rm -rf app
cp -r vulnerable-app app
# Keep the committed .env (force, since app/.env would otherwise be gitignored).
git add -A app
git add -f app/.env

git commit -m "demo: intentionally vulnerable app (10 OWASP findings for the pipeline)"

cat <<'EOF'

Created branch 'vulnerable'.
Next:
  git push -u origin vulnerable        # CI runs the gates -> expect RED
  # main remains GREEN (fixed app).
  # View the remediation diff:
  git diff vulnerable main -- app
EOF
