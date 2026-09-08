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
elif ! node -e "require.resolve('ajv/dist/2020')" >/dev/null 2>&1; then
  echo "Ajv strict validation skipped: ajv is not installed locally."
elif ! node -e "require.resolve('ajv-formats')" >/dev/null 2>&1; then
  echo "Ajv strict validation skipped: ajv-formats is not installed locally."
else
  # Register the complete local reference graph before compiling any schema.
  node <<'JS'
const fs = require('node:fs');
const Ajv = require('ajv/dist/2020');
const addFormats = require('ajv-formats');
const ajv = new Ajv({strict: true});
addFormats(ajv);
const schemas = fs.readdirSync('schemas/v1')
  .filter(name => name.endsWith('.schema.json')).sort()
  .map(name => JSON.parse(fs.readFileSync(`schemas/v1/${name}`, 'utf8')));
ajv.addSchema(schemas);
for (const schema of schemas) {
  if (!ajv.getSchema(schema.$id)) {
    throw new Error(`Schema was not compiled: ${schema.$id}`);
  }
}
JS
  echo "Ajv Draft 2020-12 strict validation passed."
fi
