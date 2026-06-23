#!/usr/bin/env node
// JavaScript port of sbomgate's core CLI surface: SBOM diff + advisory match + gate.
// Mirrors the Python reference (sbomgate/core.py). Zero dependencies, stdlib only.
import { readFileSync } from "fs";
import { fileURLToPath } from "url";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "none", "unknown"];
export function sevRank(s) {
  const i = SEVERITY_ORDER.indexOf((s || "unknown").trim().toLowerCase());
  return i < 0 ? SEVERITY_ORDER.indexOf("unknown") : i;
}

function first(d, keys, dflt = "") {
  for (const k of keys) {
    const v = d[k];
    if (v != null && (typeof v === "string" || typeof v === "number")) {
      const s = String(v).trim();
      if (s) return s;
    }
  }
  return dflt;
}

function ecoFromPurl(purl) {
  if (purl && purl.startsWith("pkg:")) return purl.slice(4).split("/", 1)[0].trim().toLowerCase();
  return "";
}

export function parseSbom(data) {
  let raw = [];
  if (Array.isArray(data)) raw = data.filter((x) => x && typeof x === "object");
  else if (data && Array.isArray(data.components)) raw = data.components;
  else if (data && Array.isArray(data.packages)) raw = data.packages;
  else throw new Error("unrecognized SBOM: no components or packages array");
  return raw.map((r) => {
    const name = first(r, ["name", "packageName"]);
    if (!name) return null;
    const purl = first(r, ["purl", "packageUrl"]);
    let eco = first(r, ["ecosystem", "type"]) || ecoFromPurl(purl);
    if (["application", "library", "framework", "container", "file"].includes(eco)) eco = ecoFromPurl(purl);
    return {
      name,
      version: first(r, ["version", "versionInfo"]),
      purl,
      maintainer: first(r, ["maintainer", "publisher", "author", "supplier", "originator"]),
      ecosystem: eco,
    };
  }).filter(Boolean);
}

function key(c) {
  const eco = (c.ecosystem || "").trim().toLowerCase();
  const n = c.name.trim().toLowerCase();
  return eco ? `${eco}:${n}` : n;
}

export function diffSboms(oldC, newC) {
  const o = Object.fromEntries(oldC.map((c) => [key(c), c]));
  const n = Object.fromEntries(newC.map((c) => [key(c), c]));
  const findings = [];
  for (const k of Object.keys(n).sort()) if (!(k in o))
    findings.push({ kind: "added", component: n[k].name, severity: "low", new: n[k].version, detail: `new dependency ${n[k].name} ${n[k].version}`.trim() });
  for (const k of Object.keys(o).sort()) if (!(k in n))
    findings.push({ kind: "removed", component: o[k].name, severity: "none", old: o[k].version, detail: `dependency ${o[k].name} ${o[k].version} removed`.trim() });
  for (const k of Object.keys(o).filter((k) => k in n).sort()) {
    const oc = o[k], nc = n[k];
    if (oc.version !== nc.version)
      findings.push({ kind: "version-change", component: nc.name, severity: "low", old: oc.version, new: nc.version, detail: `${nc.name} ${oc.version} -> ${nc.version}` });
    if (oc.maintainer && nc.maintainer && oc.maintainer !== nc.maintainer)
      findings.push({ kind: "maintainer-change", component: nc.name, severity: "high", old: oc.maintainer, new: nc.maintainer, detail: `maintainer of ${nc.name} changed (possible takeover)` });
  }
  return { old_count: oldC.length, new_count: newC.length, findings };
}

export function gate(findings, failOn = "high") {
  const t = sevRank(failOn);
  return findings.some((f) => sevRank(f.severity) <= t);
}

function loadSbom(p) { return parseSbom(JSON.parse(readFileSync(p, "utf8"))); }

function main(argv) {
  const [cmd, ...rest] = argv;
  if (cmd === "diff") {
    const d = diffSboms(loadSbom(rest[0]), loadSbom(rest[1]));
    const failed = gate(d.findings);
    console.log(JSON.stringify({ tool: "sbomgate", ...d, gate: failed ? "fail" : "pass" }, null, 2));
    return failed ? 1 : 0;
  }
  if (cmd === "--version") { console.log("sbomgate (js port)"); return 0; }
  console.log("usage: sbomgate-js diff <old.json> <new.json>");
  return 0;
}

// Run as CLI when invoked directly (works cross-platform incl. Windows paths).
try {
  if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
    process.exit(main(process.argv.slice(2)));
  }
} catch { /* imported as a module */ }
