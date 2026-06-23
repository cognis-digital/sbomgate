// Rust port of sbomgate's core CLI surface: SBOM diff + gate.
// Mirrors the Python reference (sbomgate/core.py). Single binary, no deps —
// includes a tiny hand-rolled JSON value parser so the crate stays zero-dependency.
use std::collections::BTreeMap;
use std::{env, fs, process};

mod json;
use json::Json;

const SEVERITY_ORDER: [&str; 6] = ["critical", "high", "medium", "low", "none", "unknown"];

fn sev_rank(s: &str) -> usize {
    let s = s.trim().to_lowercase();
    SEVERITY_ORDER.iter().position(|&v| v == s).unwrap_or(5)
}

#[derive(Clone, Default)]
struct Component {
    name: String,
    version: String,
    maintainer: String,
    ecosystem: String,
}

struct Finding {
    kind: String,
    component: String,
    severity: String,
    old: String,
    new: String,
}

fn first(o: &BTreeMap<String, Json>, keys: &[&str]) -> String {
    for k in keys {
        if let Some(v) = o.get(*k) {
            let s = v.as_str_lossy();
            if !s.trim().is_empty() {
                return s.trim().to_string();
            }
        }
    }
    String::new()
}

fn eco_from_purl(p: &str) -> String {
    if let Some(rest) = p.strip_prefix("pkg:") {
        return rest.split('/').next().unwrap_or("").to_lowercase();
    }
    String::new()
}

fn parse_sbom(data: &Json) -> Vec<Component> {
    let raw: Vec<&Json> = match data {
        Json::Array(a) => a.iter().collect(),
        Json::Object(o) => {
            if let Some(Json::Array(a)) = o.get("components") {
                a.iter().collect()
            } else if let Some(Json::Array(a)) = o.get("packages") {
                a.iter().collect()
            } else {
                vec![]
            }
        }
        _ => vec![],
    };
    let mut out = vec![];
    for r in raw {
        if let Json::Object(o) = r {
            let name = first(o, &["name", "packageName"]);
            if name.is_empty() {
                continue;
            }
            let purl = first(o, &["purl", "packageUrl"]);
            let mut eco = first(o, &["ecosystem", "type"]);
            if eco.is_empty() || ["application", "library", "framework", "container", "file"].contains(&eco.as_str()) {
                eco = eco_from_purl(&purl);
            }
            out.push(Component {
                name,
                version: first(o, &["version", "versionInfo"]),
                maintainer: first(o, &["maintainer", "publisher", "author", "supplier", "originator"]),
                ecosystem: eco,
            });
        }
    }
    out
}

fn key(c: &Component) -> String {
    let eco = c.ecosystem.trim().to_lowercase();
    let n = c.name.trim().to_lowercase();
    if eco.is_empty() { n } else { format!("{eco}:{n}") }
}

fn diff(old: &[Component], new: &[Component]) -> Vec<Finding> {
    let o: BTreeMap<_, _> = old.iter().map(|c| (key(c), c)).collect();
    let n: BTreeMap<_, _> = new.iter().map(|c| (key(c), c)).collect();
    let mut fs = vec![];
    for (k, c) in &n {
        if !o.contains_key(k) {
            fs.push(Finding { kind: "added".into(), component: c.name.clone(), severity: "low".into(), old: "".into(), new: c.version.clone() });
        }
    }
    for (k, c) in &o {
        if !n.contains_key(k) {
            fs.push(Finding { kind: "removed".into(), component: c.name.clone(), severity: "none".into(), old: c.version.clone(), new: "".into() });
        }
    }
    for (k, nc) in &n {
        if let Some(oc) = o.get(k) {
            if oc.version != nc.version {
                fs.push(Finding { kind: "version-change".into(), component: nc.name.clone(), severity: "low".into(), old: oc.version.clone(), new: nc.version.clone() });
            }
            if !oc.maintainer.is_empty() && !nc.maintainer.is_empty() && oc.maintainer != nc.maintainer {
                fs.push(Finding { kind: "maintainer-change".into(), component: nc.name.clone(), severity: "high".into(), old: oc.maintainer.clone(), new: nc.maintainer.clone() });
            }
        }
    }
    fs
}

fn gate(fs: &[Finding], fail_on: &str) -> bool {
    let t = sev_rank(fail_on);
    fs.iter().any(|f| sev_rank(&f.severity) <= t)
}

fn load(path: &str) -> Vec<Component> {
    let txt = fs::read_to_string(path).unwrap_or_else(|_| {
        eprintln!("sbomgate: file not found: {path}");
        process::exit(2);
    });
    parse_sbom(&Json::parse(&txt).unwrap_or(Json::Null))
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("usage: sbomgate-rs diff <old.json> <new.json>");
        return;
    }
    match args[1].as_str() {
        "--version" => println!("sbomgate (rust port)"),
        "diff" => {
            let (old, new) = (load(&args[2]), load(&args[3]));
            let fs = diff(&old, &new);
            let failed = gate(&fs, "high");
            let items: Vec<String> = fs.iter().map(|f| format!(
                "{{\"kind\":\"{}\",\"component\":\"{}\",\"severity\":\"{}\",\"old\":\"{}\",\"new\":\"{}\"}}",
                f.kind, f.component, f.severity, f.old, f.new)).collect();
            println!("{{\"tool\":\"sbomgate\",\"old_count\":{},\"new_count\":{},\"gate\":\"{}\",\"findings\":[{}]}}",
                old.len(), new.len(), if failed { "fail" } else { "pass" }, items.join(","));
            if failed { process::exit(1); }
        }
        _ => println!("usage: sbomgate-rs diff <old.json> <new.json>"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn comp(n: &str, v: &str) -> Component {
        Component { name: n.into(), version: v.into(), ..Default::default() }
    }
    #[test]
    fn sev_rank_order() {
        assert!(sev_rank("critical") < sev_rank("high"));
        assert!(sev_rank("high") < sev_rank("low"));
        assert_eq!(sev_rank("bogus"), 5);
    }
    #[test]
    fn diff_detects_added_removed_and_version() {
        let old = vec![comp("a", "1.0"), comp("b", "1.0")];
        let new = vec![comp("a", "2.0"), comp("c", "1.0")];
        let fs = diff(&old, &new);
        assert!(fs.iter().any(|f| f.kind == "added" && f.component == "c"));
        assert!(fs.iter().any(|f| f.kind == "removed" && f.component == "b"));
        assert!(fs.iter().any(|f| f.kind == "version-change" && f.component == "a"));
    }
    #[test]
    fn maintainer_change_is_high_and_gates() {
        let old = vec![Component { name: "x".into(), version: "1".into(), maintainer: "alice".into(), ecosystem: "".into() }];
        let new = vec![Component { name: "x".into(), version: "1".into(), maintainer: "mallory".into(), ecosystem: "".into() }];
        let fs = diff(&old, &new);
        assert!(fs.iter().any(|f| f.kind == "maintainer-change" && f.severity == "high"));
        assert!(gate(&fs, "high"));
    }
    #[test]
    fn parse_cyclonedx_object() {
        let j = Json::parse(r#"{"components":[{"name":"requests","version":"2.5.0","purl":"pkg:pypi/requests@2.5.0"}]}"#).unwrap();
        let cs = parse_sbom(&j);
        assert_eq!(cs.len(), 1);
        assert_eq!(cs[0].name, "requests");
        assert_eq!(cs[0].ecosystem, "pypi");
    }
}
