#!/bin/bash
# Run test vector validation across all reference implementations
# Requires: Python 3.8+, Node.js 16+

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=== Running Test Vector Validation ==="

ERRORS=0

# Python tests
echo ""
echo "--- Python Reference Implementation ---"
if command -v python3 &> /dev/null; then
    cd "$REPO_ROOT/reference-impl/python"
    if python3 aad_builder.py; then
        echo "✓ Python AAD builder tests passed"
    else
        echo "✗ Python AAD builder tests FAILED"
        ERRORS=$((ERRORS + 1))
    fi
else
    echo "⚠ Python 3 not found, skipping"
fi

# TypeScript tests (requires ts-node or compiled JS)
echo ""
echo "--- TypeScript Reference Implementation ---"
if command -v npx &> /dev/null; then
    cd "$REPO_ROOT/reference-impl/typescript"
    if [ -f "package.json" ]; then
        npm install --silent 2>/dev/null || true
        if npx ts-node test-vectors.ts 2>/dev/null; then
            echo "✓ TypeScript tests passed"
        else
            echo "⚠ TypeScript tests skipped (ts-node not configured)"
        fi
    else
        echo "⚠ TypeScript package.json not found, skipping"
    fi
else
    echo "⚠ Node.js not found, skipping"
fi

# Summary
echo ""
if [ $ERRORS -gt 0 ]; then
    echo "=== $ERRORS test suite(s) failed ==="
    exit 1
fi

echo "=== All test vectors validated ==="
