#!/usr/bin/env bash
# Run scripts/sandbox_sim.py inside a locked-down container that imitates the documented judging runtime:
# offline Linux, Python 3.12 + pqcrypto==0.4.0, read-only root filesystem, only /tmp writable, non-root user.
#
#   bash scripts/sandbox_docker.sh [GIT_REF] [TOOLKIT_PATH]
#   bash scripts/sandbox_docker.sh origin/main ../Track-4-Toolkit
#
# Needs: Docker (Docker Desktop on Windows/macOS, or Docker inside WSL), git, and a repo checkout with that ref fetched.
# Network is needed only for `docker build` (to download Python and pqcrypto); the test run itself has no network.
# NOTE: this script has not been run by its author.
set -euo pipefail

REF="${1:-origin/main}"
TOOLKIT="${2:-../Track-4-Toolkit}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[ -f "$TOOLKIT/validate.py" ] || { echo "toolkit not found at $TOOLKIT (pass its path as the second argument)"; exit 2; }
TOOLKIT="$(cd "$TOOLKIT" && pwd)"

WORK="$(mktemp -d)"
trap 'chmod -R u+w "$WORK" 2>/dev/null || true; rm -rf "$WORK"' EXIT

echo "Building a clean copy of $REF from committed files only..."
mkdir -p "$WORK/scripts"
git -C "$HERE" archive --format=tar "$REF" | tar -x -C "$WORK"
cp "$HERE/scripts/sandbox_sim.py" "$WORK/scripts/sandbox_sim.py"   # the simulator may be newer than REF
chmod -R a+rX "$WORK"                                               # readable by the non-root container user

echo "Building the image (needs network once)..."
docker build -q -t t4-sandbox -f "$HERE/scripts/sandbox.Dockerfile" "$HERE/scripts" >/dev/null

echo "Running inside the locked-down container (no network, read-only root, only /tmp writable, uid 1000)..."
docker run --rm \
  --read-only --network none \
  --user 1000:1000 --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 256 --memory 1g \
  --tmpfs /tmp:rw,mode=1777,size=256m \
  -e HOME=/tmp \
  -v "$WORK":/submission:ro \
  -v "$TOOLKIT":/toolkit:ro \
  t4-sandbox \
  python /submission/scripts/sandbox_sim.py --submission /submission --toolkit /toolkit
