#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const schemaDir = path.join(root, "schemas", "v1");
const errors = [];
let checks = 0;

function fail(message) {
  errors.push(message);
}

function check(condition, message) {
  checks += 1;
  if (!condition) fail(message);
}

function read(file) {
  return fs.readFileSync(file, "utf8");
}

function listFiles(directory, suffix) {
  return fs
    .readdirSync(directory, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith(suffix))
    .map((entry) => path.join(directory, entry.name))
    .sort();
}

function visitJson(node, callback) {
  callback(node);
  if (Array.isArray(node)) {
    for (const child of node) visitJson(child, callback);
  } else if (node && typeof node === "object") {
    for (const child of Object.values(node)) visitJson(child, callback);
  }
}

function resolvePointer(document, fragment) {
  if (!fragment) return document;
  if (!fragment.startsWith("/")) throw new Error(`unsupported fragment #${fragment}`);
  return fragment
    .slice(1)
    .split("/")
    .map((token) => token.replaceAll("~1", "/").replaceAll("~0", "~"))
    .reduce((value, token) => value[token], document);
}

const schemaFiles = listFiles(schemaDir, ".json");
const schemas = new Map();
const refGraph = new Map();

for (const file of schemaFiles) {
  try {
    const schema = JSON.parse(read(file));
    schemas.set(file, schema);
    refGraph.set(file, new Set());
    check(
      schema.$schema === "https://json-schema.org/draft/2020-12/schema",
      `${path.relative(root, file)} does not declare Draft 2020-12`,
    );
    check(typeof schema.$id === "string" && schema.$id.includes("/v1/"), `${file} has no v1 $id`);
  } catch (error) {
    fail(`${path.relative(root, file)} JSON syntax: ${error.message}`);
  }
}

for (const [file, schema] of schemas) {
  visitJson(schema, (node) => {
    if (!node || typeof node !== "object" || Array.isArray(node)) return;
    if (node.type === "object") {
      check(
        Object.hasOwn(node, "additionalProperties"),
        `${path.relative(root, file)} object omits additionalProperties`,
      );
    }
    if (typeof node.$ref !== "string" || node.$ref.startsWith("#")) return;
    const [filePart, fragment = ""] = node.$ref.split("#", 2);
    if (/^[a-z]+:/i.test(filePart)) {
      fail(`${path.relative(root, file)} uses non-local $ref ${node.$ref}`);
      return;
    }
    const target = path.resolve(path.dirname(file), filePart);
    check(target.startsWith(schemaDir + path.sep), `${file}: $ref escapes schemas/v1: ${node.$ref}`);
    check(schemas.has(target), `${path.relative(root, file)} missing $ref file ${filePart}`);
    if (!schemas.has(target)) return;
    refGraph.get(file).add(target);
    try {
      const resolved = resolvePointer(schemas.get(target), fragment);
      check(resolved !== undefined, `${path.relative(root, file)} unresolved $ref ${node.$ref}`);
    } catch (error) {
      fail(`${path.relative(root, file)} invalid $ref ${node.$ref}: ${error.message}`);
    }
  });
}

const visiting = new Set();
const visited = new Set();
function detectCycle(file, chain = []) {
  if (visiting.has(file)) {
    fail(`circular schema reference: ${[...chain, file].map((item) => path.basename(item)).join(" -> ")}`);
    return;
  }
  if (visited.has(file)) return;
  visiting.add(file);
  for (const target of refGraph.get(file) ?? []) detectCycle(target, [...chain, file]);
  visiting.delete(file);
  visited.add(file);
}
for (const file of schemaFiles) detectCycle(file);
checks += 1;

const markdownFiles = [path.join(root, "README.md"), ...listFiles(path.join(root, "docs"), ".md")];
for (const file of markdownFiles) {
  const markdown = read(file);
  const links = markdown.matchAll(/\[[^\]]+\]\(([^)]+)\)/g);
  for (const match of links) {
    const target = match[1].replace(/^<|>$/g, "").split("#", 1)[0];
    if (!target || target.startsWith("#") || /^[a-z]+:/i.test(target)) continue;
    check(fs.existsSync(path.resolve(path.dirname(file), target)), `${path.relative(root, file)} broken link ${target}`);
  }
}

const traceability = read(path.join(root, "docs", "REQUIREMENTS_TRACEABILITY.md"));
for (const prefix of ["CORE", "CTX", "LOC", "RPT", "MCP", "PERF", "COMM", "MEDIA", "AI", "AUD", "IDX", "TZ", "KW", "COC", "VIEW", "VAL"]) {
  check(new RegExp(`\\| ${prefix}-\\d{3} \\|`).test(traceability), `missing ${prefix} requirements`);
}
for (const column of ["Architecture", "Module Owner", "API", "Database", "Schema", "Phase", "\uac80\uc99d"]) {
  check(traceability.includes(column), `traceability omits ${column} linkage`);
}

const api = read(path.join(root, "docs", "API_INTERFACE.md"));
const requirementIds = [...traceability.matchAll(/\|\s*([A-Z]+(?:-[A-Z]+)*-\d{3})\s*\|/g)].map((match) => match[1]);
const duplicateRequirementIds = [...new Set(requirementIds.filter((id, index) => requirementIds.indexOf(id) !== index))];
check(duplicateRequirementIds.length === 0, "duplicate requirement IDs: " + duplicateRequirementIds.join(", "));

for (const endpoint of [
  "/sessions/{session_id}/ui-context",
  "/cases/{case_id}/context-snapshots",
  "/cases/{case_id}/analysis-bundle",
  "/cases/{case_id}/search-results",
  "/cases/{case_id}/reports",
  "/generate-draft",
  "/request-review",
  "/approve",
  "/reject",
  "/export",
  "/cases/{case_id}/analysis-profiles",
  "/cases/{case_id}/index-jobs",
  "/cases/{case_id}/index-jobs/{job_id}/pause",
  "/cases/{case_id}/index-jobs/{job_id}/resume",
  "/cases/{case_id}/index-jobs/{job_id}/cancel",
  "/cases/{case_id}/index-jobs/{job_id}/priority",
  "/cases/{case_id}/index-jobs/{job_id}/progress",
  "/cases/{case_id}/partial-results",
  "/cases/{case_id}/timezone/detect",
  "/cases/{case_id}/timezone/candidates",
  "/cases/{case_id}/timestamp-interpretations",
  "/cases/{case_id}/keyword-recommendations",
  "/cases/{case_id}/keyword-sets",
  "/cases/{case_id}/search-executions/{execution_id}/rerun",
  "/cases/{case_id}/evidence/{evidence_id}/custody-events",
  "/cases/{case_id}/evidence/{evidence_id}/hash-verifications",
  "/cases/{case_id}/evidence/{evidence_id}/custody-snapshots",
  "/cases/{case_id}/files/{file_id}/raw",
  "/cases/{case_id}/artifacts/{artifact_id}/raw",
  "/cases/{case_id}/raw-ranges",
  "/cases/{case_id}/media-extraction-jobs",
  "/cases/{case_id}/machine-extractions",
]) {
  check(api.includes(endpoint), `API design omits ${endpoint}`);
}

const apiRows = [...api.matchAll(/\|\s*\x60(GET|POST|PUT|PATCH|DELETE)\x60\s*\|\s*\x60([^\x60]+)\x60\s*\|/g)]
  .map((match) => match[1] + " " + match[2]);
const duplicateApiRows = [...new Set(apiRows.filter((row, index) => apiRows.indexOf(row) !== index))];
check(duplicateApiRows.length === 0, "duplicate API endpoints: " + duplicateApiRows.join(", "));

for (const name of [
  "common.schema.json",
  "api-response.schema.json",
  "case.schema.json",
  "ui-context.schema.json",
  "analysis-context.schema.json",
  "citation.schema.json",
  "report.schema.json",
  "ai-enrichment.schema.json",
  "evidence.schema.json",
  "file.schema.json",
  "artifact.schema.json",
  "timeline-event.schema.json",
  "search.schema.json",
  "job.schema.json",
  "analysis-profile.schema.json",
  "keyword-recommendation.schema.json",
  "chain-of-custody.schema.json",
  "machine-extraction.schema.json",
]) {
  check(schemas.has(path.join(schemaDir, name)), `missing required schema ${name}`);
  check(api.includes(name) || name === "common.schema.json", `API-to-schema map omits ${name}`);
}

const database = read(path.join(root, "docs", "DATABASE_SCHEMA.md"));
for (const table of [
  "search_queries",
  "search_results",
  "ui_context_snapshots",
  "analysis_context_snapshots",
  "analyst_annotations",
  "tags",
  "tagged_items",
  "reports",
  "report_sections",
  "report_evidence_links",
  "report_artifact_links",
  "report_timeline_links",
  "report_search_result_links",
  "report_tag_links",
  "report_citations",
  "report_exports",
  "analysis_profiles",
  "indexing_jobs",
  "indexing_job_scopes",
  "indexing_checkpoints",
  "analyzer_progress",
  "cache_entries",
  "evidence_fingerprints",
  "timezone_candidates",
  "timezone_decisions",
  "timestamp_interpretations",
  "keyword_recommendations",
  "keyword_sets",
  "keyword_set_items",
  "keyword_approvals",
  "search_executions",
  "search_execution_options",
  "custody_events",
  "custody_hash_verifications",
  "custody_snapshots",
  "custody_approvals",
  "browser_profiles",
  "browser_analysis_jobs",
  "browser_checkpoints",
  "browser_source_revisions",
  "browser_snapshot_records",
  "browser_artifacts",
  "media_analysis_jobs",
  "media_checkpoints",
  "media_source_revisions",
  "media_artifacts",
  "thumbnail_records",
  "machine_extracted_candidates",
  "candidate_review_events",
  "provider_capabilities",
  "benchmark_runs",
  "benchmark_measurements",
  "external_validation_reviews",
]) {
  check(database.includes(`\`${table}\``), `database design omits ${table}`);
}

const modules = read(path.join(root, "docs", "MODULE_RESPONSIBILITIES.md"));
for (const owner of [
  "Context Service",
  "Annotation/Tag",
  "Report Module",
  "Localization",
  "Progressive Indexing Coordinator",
  "Analysis Profile Manager",
  "Priority Job Scheduler",
  "Progress Estimator",
  "Timezone Resolver",
  "Timestamp Normalizer",
  "Keyword Recommendation Port",
  "Keyword Set Manager",
  "Search Reproduction Manager",
  "Chain of Custody Ledger",
  "Custody Verification Service",
  "Raw Evidence Locator",
  "Machine Extraction Port",
  "Media Extraction Candidate Store",
  "External Validation Plan",
]) {
  check(modules.includes(owner), `module ownership omits ${owner}`);
}
check(traceability.includes("\uc18c\uc720\uad8c \uc911\ubcf5 \uac80\uc0ac"), "module/database ownership audit is missing");


function definition(schemaName, definitionName) {
  return schemas.get(path.join(schemaDir, schemaName))?.$defs?.[definitionName];
}

function checkRequired(schemaName, definitionName, fields) {
  const required = new Set(definition(schemaName, definitionName)?.required ?? []);
  for (const field of fields) {
    check(required.has(field), schemaName + " " + definitionName + " requires " + field);
  }
}

const common = schemas.get(path.join(schemaDir, "common.schema.json"));
check(JSON.stringify(common).includes("IANA"), "common timezone contract does not document IANA identifiers");
check(definition("common.schema.json", "timestampInterpretation") !== undefined, "common schema omits timestampInterpretation");
check(definition("common.schema.json", "partialResult") !== undefined, "common schema omits partialResult");
for (const fileName of ["ARCHITECTURE.md", "API_INTERFACE.md", "JSON_SCHEMAS.md"]) {
  check(read(path.join(root, "docs", fileName)).includes("IANA"), fileName + " omits IANA timezone policy");
}

const jsonSchemasDoc = read(path.join(root, "docs", "JSON_SCHEMAS.md"));
const expectedCustodyEvents = [
  "ACQUISITION", "RECEIVED", "TRANSFERRED", "STORED", "OPENED",
  "MOUNTED", "ANALYZED", "HASH_VERIFIED", "COPIED", "EXPORTED",
  "RETURNED", "RELEASED", "ARCHIVED", "DISPOSED", "CORRECTION",
];
const custodyEvents = definition("chain-of-custody.schema.json", "custodyEvent")?.properties?.event_type?.enum ?? [];
check(JSON.stringify(custodyEvents) === JSON.stringify(expectedCustodyEvents), "custody event enum differs from canonical contract");
for (const eventName of expectedCustodyEvents) {
  check(jsonSchemasDoc.includes(eventName), "JSON schema guide omits custody event " + eventName);
}
checkRequired("chain-of-custody.schema.json", "custodyEvent", [
  "event_id", "case_id", "evidence_id", "event_type", "actor_id", "actor_name",
  "actor_role", "organization", "source_location", "destination_location", "action",
  "reason", "occurred_at_utc", "displayed_at", "timezone", "tool_name", "tool_version",
  "previous_hash", "current_hash", "notes", "created_at", "immutable_revision",
  "previous_event_hash", "event_hash", "approval",
]);

checkRequired("keyword-recommendation.schema.json", "keywordCandidate", [
  "id", "keyword", "type", "reason", "scope", "citations", "confidence", "status",
]);
const keywordText = JSON.stringify(schemas.get(path.join(schemaDir, "keyword-recommendation.schema.json")));
check(keywordText.includes("PENDING_REVIEW"), "keyword review status omits PENDING_REVIEW");
check(keywordText.includes("minItems"), "keyword candidate citations are not constrained to be non-empty");

checkRequired("machine-extraction.schema.json", "machineExtraction", [
  "extraction_id", "evidence_id", "file_id", "media_type", "extraction_type",
  "extracted_text", "confidence", "language", "engine_id", "engine_version",
  "frame_number", "timestamp_offset_ms", "source_region", "source_locator",
  "analyst_status", "citations", "created_at",
]);
const machineStatuses = definition("machine-extraction.schema.json", "machineExtraction")?.properties?.analyst_status?.enum ?? [];
check(
  JSON.stringify(machineStatuses) === JSON.stringify(["UNREVIEWED", "ACCEPTED", "REJECTED", "CORRECTED"]),
  "machine extraction review enum differs from contract",
);

checkRequired("job.schema.json", "progress", [
  "processed_items", "estimated_total_items", "progress_percent",
  "throughput_items_per_second", "elapsed_seconds", "estimated_remaining_seconds",
  "estimate_confidence", "current_analyzer", "worker_count", "cache_hits",
  "cache_misses", "partial_results_available", "status",
]);
const jobText = JSON.stringify(schemas.get(path.join(schemaDir, "job.schema.json")));
check(jobText.includes("result_completeness"), "job schema omits result completeness");

const analysisContextText = JSON.stringify(schemas.get(path.join(schemaDir, "analysis-context.schema.json")));
for (const field of ["is_partial", "scope", "scope_revision"]) {
  check(analysisContextText.includes(field), "analysis context omits " + field);
}

const reportSectionEnum = definition("report.schema.json", "reportSection")?.properties?.section_type?.enum ?? [];
for (const section of [
  "INDEXING_SCOPE", "TIMEZONE_POLICY", "KEYWORD_SEARCH", "CHAIN_OF_CUSTODY",
  "HASH_VERIFICATION", "MACHINE_EXTRACTION", "EXTERNAL_VALIDATION",
]) {
  check(reportSectionEnum.includes(section), "report schema omits section " + section);
  check(jsonSchemasDoc.includes(section), "JSON schema guide omits report section " + section);
}
const reportClassifications = definition("report.schema.json", "reportStatement")?.properties?.classification?.enum ?? [];
for (const classification of [
  "OBSERVED_FACT", "ANALYST_ANNOTATION", "MACHINE_EXTRACTED_CANDIDATE",
  "AI_INFERENCE", "AI_RECOMMENDATION",
]) {
  check(reportClassifications.includes(classification), "report classification omits " + classification);
}

const bannedSchemaProperties = new Set(["provider", "model", "prompt", "api_key", "credential"]);
for (const [file, schema] of schemas) {
  visitJson(schema, (node) => {
    if (!node || typeof node !== "object" || Array.isArray(node) || !node.properties) return;
    for (const key of Object.keys(node.properties)) {
      check(!bannedSchemaProperties.has(key), `${path.relative(root, file)} exposes banned core property ${key}`);
    }
  });
}

check(fs.existsSync(path.join(root, "tools", "validate_design_basic.py")), "basic validation fallback is missing");

for (const sourceDirectory of ["mcp", "prompts"]) {
  check(!fs.existsSync(path.join(root, sourceDirectory)), `forbidden implementation directory exists: ${sourceDirectory}`);
}

if (errors.length > 0) {
  console.error(`Design validation failed with ${errors.length} error(s):`);
  for (const error of errors) console.error(`- ${error}`);
  process.exit(1);
}

console.log(`Design validation passed (${checks} checks, ${schemaFiles.length} schemas).`);
