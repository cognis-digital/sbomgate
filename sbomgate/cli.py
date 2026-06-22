"""Command-line interface for SBOMGATE.

Primary subcommand: `scan` (diff old vs new SBOM + vuln match + gate).
Also: `diff`, `vulns`, and `--version`.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    Finding,
    DiffResult,
    load_sbom,
    diff_sboms,
    match_vulnerabilities,
    load_advisories,
    gate,
    to_sarif,
    _sev_rank,
)

_SEV_GLYPH = {
    "critical": "!!",
    "high": "! ",
    "medium": "~ ",
    "low": ". ",
    "none": "  ",
    "unknown": "? ",
}


def _print_table(findings: List[Finding], diff: Optional[DiffResult], failed: bool) -> None:
    if diff is not None:
        print(f"SBOM diff: {diff.old_count} -> {diff.new_count} components")
        summ = diff.summary()
        if summ:
            print("  " + "  ".join(f"{k}={v}" for k, v in sorted(summ.items())))
        print("")
    if not findings:
        print("No findings.")
    else:
        name_w = max((len(f.component) for f in findings), default=9)
        name_w = max(name_w, len("component"))
        print(f"{'SEV':<4} {'KIND':<17} {'COMPONENT':<{name_w}}  DETAIL")
        print(f"{'-'*4} {'-'*17} {'-'*name_w}  {'-'*30}")
        for f in findings:
            glyph = _SEV_GLYPH.get(f.severity, "? ")
            detail = f.detail
            if f.advisory_id:
                detail = f"[{f.advisory_id}] {detail}"
            print(f"{glyph:<4} {f.kind:<17} {f.component:<{name_w}}  {detail}")
    print("")
    print(f"GATE: {'FAIL' if failed else 'PASS'}  ({len(findings)} finding(s))")


def _emit(findings: List[Finding], diff: Optional[DiffResult], failed: bool, fmt: str) -> None:
    if fmt == "sarif":
        print(json.dumps(
            to_sarif(findings, tool_name=TOOL_NAME, tool_version=TOOL_VERSION),
            indent=2, sort_keys=True,
        ))
    elif fmt == "json":
        payload = {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "gate": "fail" if failed else "pass",
            "finding_count": len(findings),
            "findings": [f.to_dict() for f in findings],
        }
        if diff is not None:
            payload["diff"] = {
                "old_count": diff.old_count,
                "new_count": diff.new_count,
                "summary": diff.summary(),
            }
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        _print_table(findings, diff, failed)


def _maybe_enrich(args: argparse.Namespace, findings: List[Finding]) -> None:
    """Fold CISA-KEV + EPSS into vulnerability findings when --enrich is set."""
    if not getattr(args, "enrich", False):
        return
    from .feeds import enrich_findings
    enrich_findings(findings, offline=getattr(args, "offline", False))


def _run_scan(args: argparse.Namespace) -> int:
    new_comps = load_sbom(args.new)
    findings: List[Finding] = []
    diff: Optional[DiffResult] = None

    if args.old:
        old_comps = load_sbom(args.old)
        diff = diff_sboms(old_comps, new_comps)
        findings.extend(diff.findings)

    if args.advisories:
        advisories = load_advisories(args.advisories)
        findings.extend(match_vulnerabilities(new_comps, advisories))

    _maybe_enrich(args, findings)
    findings.sort(key=lambda f: (_sev_rank(f.severity), f.kind, f.component))
    failed = gate(findings, fail_on=args.fail_on)
    _emit(findings, diff, failed, args.format)
    return 1 if failed else 0


def _run_diff(args: argparse.Namespace) -> int:
    old_comps = load_sbom(args.old)
    new_comps = load_sbom(args.new)
    diff = diff_sboms(old_comps, new_comps)
    findings = sorted(diff.findings, key=lambda f: (_sev_rank(f.severity), f.kind, f.component))
    failed = gate(findings, fail_on=args.fail_on)
    _emit(findings, diff, failed, args.format)
    return 1 if failed else 0


def _run_vulns(args: argparse.Namespace) -> int:
    comps = load_sbom(args.sbom)
    advisories = load_advisories(args.advisories)
    findings = match_vulnerabilities(comps, advisories)
    _maybe_enrich(args, findings)
    findings.sort(key=lambda f: (_sev_rank(f.severity), f.kind, f.component))
    failed = gate(findings, fail_on=args.fail_on)
    _emit(findings, None, failed, args.format)
    return 1 if failed else 0


def _run_feeds(args: argparse.Namespace) -> int:
    from . import feeds
    action = getattr(args, "feeds_action", None)
    if action == "list" or action is None:
        return feeds.cli_list()
    if action == "update":
        return feeds.cli_update(args.ids)
    if action == "get":
        return feeds.cli_get(args.id, offline=args.offline)
    return feeds.cli_list()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Continuous SBOM diff & vulnerability watch with maintainer-change tracking.",
        epilog="Exit code 1 when the gate fails (a finding meets/exceeds --fail-on severity).",
    )
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")

    def add_common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--format", choices=["table", "json", "sarif"], default="table",
                        help="output format (default: table). 'sarif' emits SARIF 2.1.0 for code-scanning")
        sp.add_argument("--fail-on", choices=["critical", "high", "medium", "low"],
                        default="high", help="min severity that fails the gate (default: high)")
        sp.add_argument("--enrich", action="store_true",
                        help="enrich vuln findings with CISA-KEV (known-exploited) + EPSS scores")
        sp.add_argument("--offline", action="store_true",
                        help="air-gap mode: serve feed data from cache only, never hit the network")

    sub = p.add_subparsers(dest="command", metavar="<command>")

    sp_scan = sub.add_parser("scan", help="diff two SBOMs and/or match vulnerabilities, then gate")
    sp_scan.add_argument("new", help="path to the current/new SBOM JSON")
    sp_scan.add_argument("--old", help="path to the previous SBOM JSON (enables diff)")
    sp_scan.add_argument("--advisories", help="path to a local advisory feed JSON")
    add_common(sp_scan)
    sp_scan.set_defaults(func=_run_scan)

    sp_diff = sub.add_parser("diff", help="diff two SBOMs (added/removed/version/maintainer)")
    sp_diff.add_argument("old", help="path to the previous SBOM JSON")
    sp_diff.add_argument("new", help="path to the current SBOM JSON")
    add_common(sp_diff)
    sp_diff.set_defaults(func=_run_diff)

    sp_vulns = sub.add_parser("vulns", help="match one SBOM against a local advisory feed")
    sp_vulns.add_argument("sbom", help="path to the SBOM JSON")
    sp_vulns.add_argument("advisories", help="path to a local advisory feed JSON")
    add_common(sp_vulns)
    sp_vulns.set_defaults(func=_run_vulns)

    # feeds: manage the bundled CISA-KEV / EPSS / OSV threat-intel feeds.
    sp_feeds = sub.add_parser(
        "feeds",
        help="list/update/get the bundled CISA-KEV, EPSS and OSV feeds (edge/air-gap)",
    )
    feeds_sub = sp_feeds.add_subparsers(dest="feeds_action", metavar="<action>")
    fl = feeds_sub.add_parser("list", help="list this tool's relevant feeds + cache age")
    fl.set_defaults(func=_run_feeds)
    fu = feeds_sub.add_parser("update", help="fetch + cache feeds (defaults to all relevant)")
    fu.add_argument("ids", nargs="*", help="feed ids (cisa-kev epss osv); empty = all")
    fu.set_defaults(func=_run_feeds)
    fg = feeds_sub.add_parser("get", help="print a cached/fetched feed")
    fg.add_argument("id", help="feed id: cisa-kev | epss | osv")
    fg.add_argument("--offline", action="store_true", help="serve from cache only")
    fg.set_defaults(func=_run_feeds)
    sp_feeds.set_defaults(func=_run_feeds, feeds_action=None)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        print(f"{TOOL_NAME}: file not found: {exc.filename}", file=sys.stderr)
        return 2
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"{TOOL_NAME}: invalid input: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
