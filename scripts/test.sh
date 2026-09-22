#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Running Java tests ==="
cd "$REPO_ROOT/java"
if ! command -v mvn >/dev/null 2>&1; then
  echo "ERROR: mvn not found on PATH — Java tests cannot run." >&2
  echo "  Install Maven (e.g. 'brew install maven'), or fall back to:" >&2
  echo "    javac --release 17 + JUnit standalone console jar (see AGENTS.md)" >&2
  exit 1
fi
mvn test

echo ""
echo "=== Running JavaScript tests ==="
cd "$REPO_ROOT/javascript" && pnpm install && pnpm -r test

echo ""
echo "=== All tests passed ==="
