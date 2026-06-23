// Smoke test for the JS port — stdlib `node:assert`, no dev deps.
import assert from "node:assert";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { parseSbom, diffSboms, gate, sevRank } from "./index.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, "..", "fixtures");
import { readFileSync } from "node:fs";
const load = (f) => parseSbom(JSON.parse(readFileSync(join(fixtures, f), "utf8")));

let passed = 0;
function check(name, fn) { fn(); passed++; console.log("ok -", name); }

check("sevRank orders critical < high < low", () => {
  assert.ok(sevRank("critical") < sevRank("high"));
  assert.ok(sevRank("high") < sevRank("low"));
  assert.strictEqual(sevRank("nonsense"), sevRank("unknown"));
});

check("parseSbom reads CycloneDX + derives ecosystem", () => {
  const cs = load("sbom-new.json");
  assert.strictEqual(cs.length, 4);
  const req = cs.find((c) => c.name === "requests");
  assert.strictEqual(req.version, "2.5.0");
  assert.strictEqual(req.ecosystem, "pypi");
});

check("diff detects added/removed/version/maintainer", () => {
  const d = diffSboms(load("sbom-old.json"), load("sbom-new.json"));
  assert.strictEqual(d.old_count, 4);
  assert.strictEqual(d.new_count, 4);
  const kinds = d.findings.map((f) => f.kind);
  assert.ok(d.findings.some((f) => f.kind === "added" && f.component === "shady-logger"));
  assert.ok(d.findings.some((f) => f.kind === "removed" && f.component === "colorama"));
  assert.ok(d.findings.some((f) => f.kind === "version-change" && f.component === "requests"));
  const mc = d.findings.find((f) => f.kind === "maintainer-change");
  assert.ok(mc && mc.severity === "high" && mc.component === "leftpad-utils");
  assert.ok(kinds.length >= 4);
});

check("gate fails on maintainer-change (high)", () => {
  const d = diffSboms(load("sbom-old.json"), load("sbom-new.json"));
  assert.strictEqual(gate(d.findings, "high"), true);
});

check("gate passes for an empty finding set", () => {
  assert.strictEqual(gate([], "low"), false);
});

console.log(`\n${passed} JS port checks passed`);
