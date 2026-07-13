#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

node tools/validate_design.mjs
jq empty schemas/v1/*.json

AJV=(npx --yes \
  --package=ajv-cli@5.0.0 \
  --package=ajv-formats@3.0.1 \
  ajv compile)
AJV_FLAGS=(
  --spec=draft2020 \
  --strict=true \
  -c ajv-formats)

"${AJV[@]}" "${AJV_FLAGS[@]}" \
  -s schemas/v1/common.schema.json

"${AJV[@]}" "${AJV_FLAGS[@]}" \
  -s 'schemas/v1/{citation,ui-context}.schema.json' \
  -r schemas/v1/common.schema.json

"${AJV[@]}" "${AJV_FLAGS[@]}" \
  -s schemas/v1/analysis-context.schema.json \
  -r schemas/v1/common.schema.json \
  -r schemas/v1/citation.schema.json \
  -r schemas/v1/ui-context.schema.json

"${AJV[@]}" "${AJV_FLAGS[@]}" \
  -s 'schemas/v1/{ai-enrichment,api-response,artifact,case,evidence,file,job,report,search,timeline-event}.schema.json' \
  -r schemas/v1/common.schema.json \
  -r schemas/v1/citation.schema.json \
  -r schemas/v1/ui-context.schema.json \
  -r schemas/v1/analysis-context.schema.json

echo "JSON syntax and Ajv strict validation passed."
