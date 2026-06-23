// Go port of sbomgate's core CLI surface: SBOM diff + gate.
// Mirrors the Python reference (sbomgate/core.py). Single binary, stdlib only.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

var severityOrder = []string{"critical", "high", "medium", "low", "none", "unknown"}

func sevRank(s string) int {
	s = strings.ToLower(strings.TrimSpace(s))
	for i, v := range severityOrder {
		if v == s {
			return i
		}
	}
	return len(severityOrder) - 1
}

type Component struct {
	Name, Version, Purl, Maintainer, Ecosystem string
}

type Finding struct {
	Kind      string `json:"kind"`
	Component string `json:"component"`
	Severity  string `json:"severity"`
	Detail    string `json:"detail"`
	Old       string `json:"old,omitempty"`
	New       string `json:"new,omitempty"`
}

func first(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			switch t := v.(type) {
			case string:
				if s := strings.TrimSpace(t); s != "" {
					return s
				}
			case float64:
				return fmt.Sprintf("%v", t)
			}
		}
	}
	return ""
}

func ecoFromPurl(p string) string {
	if strings.HasPrefix(p, "pkg:") {
		return strings.ToLower(strings.SplitN(p[4:], "/", 2)[0])
	}
	return ""
}

func parseSbom(data any) []Component {
	var raw []any
	switch d := data.(type) {
	case []any:
		raw = d
	case map[string]any:
		if c, ok := d["components"].([]any); ok {
			raw = c
		} else if p, ok := d["packages"].([]any); ok {
			raw = p
		}
	}
	var out []Component
	for _, r := range raw {
		m, ok := r.(map[string]any)
		if !ok {
			continue
		}
		name := first(m, "name", "packageName")
		if name == "" {
			continue
		}
		purl := first(m, "purl", "packageUrl")
		eco := first(m, "ecosystem", "type")
		if eco == "" || eco == "application" || eco == "library" || eco == "framework" || eco == "container" || eco == "file" {
			eco = ecoFromPurl(purl)
		}
		out = append(out, Component{name, first(m, "version", "versionInfo"), purl,
			first(m, "maintainer", "publisher", "author", "supplier", "originator"), eco})
	}
	return out
}

func key(c Component) string {
	eco := strings.ToLower(strings.TrimSpace(c.Ecosystem))
	n := strings.ToLower(strings.TrimSpace(c.Name))
	if eco != "" {
		return eco + ":" + n
	}
	return n
}

func index(cs []Component) map[string]Component {
	m := map[string]Component{}
	for _, c := range cs {
		m[key(c)] = c
	}
	return m
}

func diffSboms(oldC, newC []Component) ([]Finding, int, int) {
	o, n := index(oldC), index(newC)
	var fs []Finding
	var nk []string
	for k := range n {
		nk = append(nk, k)
	}
	sort.Strings(nk)
	for _, k := range nk {
		if _, ok := o[k]; !ok {
			fs = append(fs, Finding{"added", n[k].Name, "low", "new dependency " + n[k].Name, "", n[k].Version})
		}
	}
	var ok2 []string
	for k := range o {
		ok2 = append(ok2, k)
	}
	sort.Strings(ok2)
	for _, k := range ok2 {
		if _, ok := n[k]; !ok {
			fs = append(fs, Finding{"removed", o[k].Name, "none", "dependency removed", o[k].Version, ""})
		}
	}
	for _, k := range nk {
		oc, ok := o[k]
		if !ok {
			continue
		}
		nc := n[k]
		if oc.Version != nc.Version {
			fs = append(fs, Finding{"version-change", nc.Name, "low", nc.Name + " " + oc.Version + " -> " + nc.Version, oc.Version, nc.Version})
		}
		if oc.Maintainer != "" && nc.Maintainer != "" && oc.Maintainer != nc.Maintainer {
			fs = append(fs, Finding{"maintainer-change", nc.Name, "high", "maintainer changed (possible takeover)", oc.Maintainer, nc.Maintainer})
		}
	}
	return fs, len(oldC), len(newC)
}

func gate(fs []Finding, failOn string) bool {
	t := sevRank(failOn)
	for _, f := range fs {
		if sevRank(f.Severity) <= t {
			return true
		}
	}
	return false
}

func loadSbom(path string) []Component {
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sbomgate: file not found:", path)
		os.Exit(2)
	}
	var data any
	json.Unmarshal(b, &data)
	return parseSbom(data)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: sbomgate-go diff <old.json> <new.json>")
		return
	}
	switch os.Args[1] {
	case "--version":
		fmt.Println("sbomgate (go port)")
	case "diff":
		fs, oc, nc := diffSboms(loadSbom(os.Args[2]), loadSbom(os.Args[3]))
		failed := gate(fs, "high")
		g := "pass"
		if failed {
			g = "fail"
		}
		out, _ := json.MarshalIndent(map[string]any{
			"tool": "sbomgate", "old_count": oc, "new_count": nc, "findings": fs, "gate": g,
		}, "", "  ")
		fmt.Println(string(out))
		if failed {
			os.Exit(1)
		}
	default:
		fmt.Println("usage: sbomgate-go diff <old.json> <new.json>")
	}
}
