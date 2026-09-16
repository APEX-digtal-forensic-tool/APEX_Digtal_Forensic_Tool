// Run with --disallow-code-generation-from-strings to enforce the renderer's CSP contract.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { validate_case, validate_file } from "../src/contracts/validators.js";
const fixture = JSON.parse(
  await readFile(
    new URL("../src/__fixtures__/core.json", import.meta.url),
    "utf8",
  ),
);
assert(validate_case(fixture.cases[0]));
assert(validate_file(fixture.files.items[0]));
assert(!validate_file({ id: "incomplete" }));
console.log("Canonical validators without eval/Function: PASS");
