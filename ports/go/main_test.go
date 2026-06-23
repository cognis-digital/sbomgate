package main

import "testing"

func comp(n, v string) Component { return Component{Name: n, Version: v} }

func TestSevRank(t *testing.T) {
	if sevRank("critical") >= sevRank("high") {
		t.Fatal("critical should rank below high")
	}
	if sevRank("bogus") != 5 {
		t.Fatal("unknown severity should rank last")
	}
}

func TestDiffAddedRemovedVersion(t *testing.T) {
	old := []Component{comp("a", "1.0"), comp("b", "1.0")}
	new := []Component{comp("a", "2.0"), comp("c", "1.0")}
	fs, oc, nc := diffSboms(old, new)
	if oc != 2 || nc != 2 {
		t.Fatalf("counts wrong: %d %d", oc, nc)
	}
	var added, removed, ver bool
	for _, f := range fs {
		if f.Kind == "added" && f.Component == "c" {
			added = true
		}
		if f.Kind == "removed" && f.Component == "b" {
			removed = true
		}
		if f.Kind == "version-change" && f.Component == "a" {
			ver = true
		}
	}
	if !added || !removed || !ver {
		t.Fatalf("missing finding: added=%v removed=%v ver=%v", added, removed, ver)
	}
}

func TestMaintainerChangeGates(t *testing.T) {
	old := []Component{{Name: "x", Version: "1", Maintainer: "alice"}}
	new := []Component{{Name: "x", Version: "1", Maintainer: "mallory"}}
	fs, _, _ := diffSboms(old, new)
	found := false
	for _, f := range fs {
		if f.Kind == "maintainer-change" && f.Severity == "high" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected high-severity maintainer-change")
	}
	if !gate(fs, "high") {
		t.Fatal("gate should fail on high")
	}
}

func TestParseCycloneDX(t *testing.T) {
	data := map[string]any{"components": []any{
		map[string]any{"name": "requests", "version": "2.5.0", "purl": "pkg:pypi/requests@2.5.0"},
	}}
	cs := parseSbom(data)
	if len(cs) != 1 || cs[0].Name != "requests" || cs[0].Ecosystem != "pypi" {
		t.Fatalf("bad parse: %+v", cs)
	}
}
