import { readdir, readFile, mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { compile } from "json-schema-to-typescript";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import standalone from "ajv/dist/standalone/index.js";
import { build } from "esbuild";
const root = resolve("../schemas/v1");
const files = (await readdir(root)).filter((x) => x.endsWith(".schema.json"));
const schemas = Object.fromEntries(
  await Promise.all(
    files.map(async (f) => [
      f,
      JSON.parse(await readFile(resolve(root, f), "utf8")),
    ]),
  ),
);
await mkdir("src/contracts/generated", { recursive: true });
// Compile the exact canonical registry at build time: the renderer prohibits eval/Function.
const names = {
  case: "CaseRecord",
  evidence: "EvidenceRecord",
  file: "FileNode",
  artifact: "ArtifactRecord",
  "gui-session-context": "GuiContext",
  "runtime-capability-report": "CapabilityReport",
  "view-projection": "ViewProjection",
  job: "JobRecord",
  "report-record": "ReportRecord",
  "report-version": "ReportVersion",
  "machine-extracted-candidate": "CandidateRecord",
};
const ajv = new Ajv2020({
  strict: false,
  validateFormats: true,
  code: { source: true, esm: true },
});
addFormats(ajv);
for (const schema of Object.values(schemas)) ajv.addSchema(schema);
const exports = Object.fromEntries(
  Object.keys(names).map((name) => [
    "validate_" + name.replaceAll("-", "_"),
    schemas[name + ".schema.json"].$id,
  ]),
);
await build({
  stdin: {
    contents: standalone(ajv, exports),
    resolveDir: process.cwd(),
    loader: "js",
  },
  bundle: true,
  platform: "browser",
  format: "esm",
  outfile: "src/contracts/validators.js",
  banner: {
    js: "/* Generated from canonical APEX schemas; run npm run contracts. */",
  },
});
await writeFile(
  "src/contracts/validators.d.ts",
  Object.keys(exports)
    .map((name) => `export declare function ${name}(data: unknown): boolean;`)
    .join("\n") + "\n",
);
function expand(value, file, stack = []) {
  if (Array.isArray(value)) return value.map((v) => expand(v, file, stack));
  if (!value || typeof value !== "object") return value;
  let base = {};
  if (value.$ref) {
    const [url, fragment = ""] = value.$ref.split("#");
    const target = url ? url.split("/").pop() : file;
    const key = target + "#" + fragment;
    if (stack.includes(key)) {
      if (
        ![
          "common.schema.json#/$defs/restrictedContractJsonValue",
          "common.schema.json#/$defs/restrictedContractObject",
        ].includes(key)
      )
        throw new Error("Unsupported recursive type: " + key);
      return {
        tsType: key.endsWith("Object")
          ? "{[key:string]:JsonValue}"
          : "JsonValue",
      };
    }
    let node = schemas[target];
    for (const part of fragment.split("/").filter(Boolean))
      node =
        node[decodeURIComponent(part).replace(/~1/g, "/").replace(/~0/g, "~")];
    base = expand(node, target, [...stack, key]);
  }
  for (const [k, v] of Object.entries(value))
    if (!["$ref", "$defs", "definitions", "$id", "$schema"].includes(k))
      base[k] = expand(v, file, stack);
  return base;
}
for (const [file, name] of Object.entries(names)) {
  const schema = expand(schemas[file + ".schema.json"], file + ".schema.json");
  schema.title = name;
  const output = await compile(schema, name, {
    unreachableDefinitions: false,
    bannerComment:
      "/* Generated from canonical APEX schemas; run npm run contracts. */",
  });
  await writeFile(
    `src/contracts/generated/${file}.ts`,
    output +
      "\nexport type JsonValue = null | boolean | number | string | JsonValue[] | {[key:string]:JsonValue};\n",
  );
}
