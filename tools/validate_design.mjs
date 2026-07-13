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
for (const prefix of ["CTX", "LOC", "RPT", "MCP", "PERF", "COMM", "MEDIA", "AI", "AUD"]) {
  check(new RegExp(`\\| ${prefix}-\\d{3} \\|`).test(traceability), `missing ${prefix} requirements`);
}
for (const column of ["Architecture", "API", "Database", "Schema", "Phase", "검증"]) {
  check(traceability.includes(column), `traceability omits ${column} linkage`);
}

const api = read(path.join(root, "docs", "API_INTERFACE.md"));
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
]) {
  check(api.includes(endpoint), `API design omits ${endpoint}`);
}

for (const name of [
  "common.schema.json",
  "api-response.schema.json",
  "case.schema.json",
  "ui-context.schema.json",
  "analysis-context.schema.json",
  "citation.schema.json",
  "report.schema.json",
  "ai-enrichment.schema.json",
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
]) {
  check(database.includes(`\`${table}\``), `database design omits ${table}`);
}

const modules = read(path.join(root, "docs", "MODULE_RESPONSIBILITIES.md"));
for (const owner of ["Context Service", "Annotation/Tag", "Report Module", "Localization"]) {
  check(modules.includes(owner), `module ownership omits ${owner}`);
}
check(traceability.includes("## 9. 소유권 중복 검사"), "module/database ownership audit is missing");

const bannedSchemaProperties = new Set(["provider", "model", "prompt", "api_key", "credential"]);
for (const [file, schema] of schemas) {
  visitJson(schema, (node) => {
    if (!node || typeof node !== "object" || Array.isArray(node) || !node.properties) return;
    for (const key of Object.keys(node.properties)) {
      check(!bannedSchemaProperties.has(key), `${path.relative(root, file)} exposes banned core property ${key}`);
    }
  });
}

for (const sourceDirectory of ["src", "mcp", "prompts"]) {
  check(!fs.existsSync(path.join(root, sourceDirectory)), `forbidden implementation directory exists: ${sourceDirectory}`);
}

if (errors.length > 0) {
  console.error(`Design validation failed with ${errors.length} error(s):`);
  for (const error of errors) console.error(`- ${error}`);
  process.exit(1);
}

console.log(`Design validation passed (${checks} checks, ${schemaFiles.length} schemas).`);
