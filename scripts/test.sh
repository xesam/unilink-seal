#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Running Java tests ==="
cd "$REPO_ROOT/java" && mvn test

echo ""
echo "=== Running JavaScript tests ==="
cd "$REPO_ROOT/javascript" && pnpm install && pnpm -r test

echo ""
echo "=== All tests passed ==="
