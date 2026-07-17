#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if command -v python3 >/dev/null 2>&1; then
  python3 tools/validate_design_basic.py
else
  echo "Basic validation failed: python3 is not available." >&2
  exit 1
fi

if command -v node >/dev/null 2>&1; then
  node tools/validate_design.mjs
else
  echo "Node validation skipped: node is not available; basic validation passed."
fi

if ! command -v node >/dev/null 2>&1; then
  echo "Ajv strict validation skipped: node is not available."
elif ! command -v npx >/dev/null 2>&1; then
  echo "Ajv strict validation skipped: npx is not available."
elif ! npx --no-install ajv --version >/dev/null 2>&1; then
  echo "Ajv strict validation skipped: ajv-cli is not installed locally."
elif ! node -e "require.resolve('ajv-formats')" >/dev/null 2>&1; then
  echo "Ajv strict validation skipped: ajv-formats is not installed locally."
else
  npx --no-install ajv compile \
    --spec=draft2020 \
    --strict=true \
    -c ajv-formats \
    -s 'schemas/v1/*.schema.json'
  echo "Ajv Draft 2020-12 strict validation passed."
fi
