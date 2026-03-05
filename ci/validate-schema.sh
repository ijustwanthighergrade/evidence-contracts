#!/bin/bash
# Validate JSON Schema files
# Requires: ajv-cli (npm install -g ajv-cli)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
SCHEMAS_DIR="$REPO_ROOT/schemas"

echo "=== Validating JSON Schemas ==="

# Check if ajv is installed
if ! command -v ajv &> /dev/null; then
    echo "Error: ajv-cli not found. Install with: npm install -g ajv-cli"
    exit 1
fi

# Validate each schema file
ERRORS=0

for schema in "$SCHEMAS_DIR"/*.schema.json; do
    if [ -f "$schema" ]; then
        echo -n "Validating $(basename "$schema")... "
        if ajv compile -s "$schema" --spec=draft2020 2>/dev/null; then
            echo "✓"
        else
            echo "✗ FAILED"
            ERRORS=$((ERRORS + 1))
        fi
    fi
done

if [ $ERRORS -gt 0 ]; then
    echo ""
    echo "=== $ERRORS schema(s) failed validation ==="
    exit 1
fi

echo ""
echo "=== All schemas valid ==="
