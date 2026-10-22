"""Scan one ZIP package with the same pinned engines as the repository action.

This is an operator CLI, not a public HTTP server. Uploaded bytes never become
Git commits, shell arguments derived from member names, or executable setup.
"""
from __future__ import annotations

import argparse
from collections import Counter
import datetime as dt
import html
import json
import os
from pathlib import Path
import sys
import tempfile

from .archive import stage_archive
from .guidance import guidance_for
from .runner import scan_engine
from .staging import _plain_path

MAX_REVIEW_GROUPS = 500


def review_groups(engine: dict) -> tuple[list[dict], bool]:
    """Bound presentation work; all original findings remain in JSON evidence."""
    counts = Counter((f["rule_id"], f["severity"]) for f in engine["findings"])
    by_rule = {}
    for item in engine.get("finding_diagnostics", {}).get("locations", []):
        by_rule.setdefault((item["rule_id"], item["severity"]), []).append(f"{item['file']}:{item['line']}")
    return ([{"rule_id": rule, "severity": severity, "count": count,
              "locations": by_rule.get((rule, severity), []),
              **guidance_for(engine["engine"], rule)}
             for (rule, severity), count in list(counts.items())[:MAX_REVIEW_GROUPS]],
            len(counts) > MAX_REVIEW_GROUPS)


def read_state(state: Path) -> tuple[dict, dict]:
    """Only operator-owned resolve/install output is accepted as scanner state."""
    pins = json.loads((state / "pins.json").read_text(encoding="utf-8"))
    installed = json.loads((state / "installed.json").read_text(encoding="utf-8"))
    programs = {"cisco": "skill-scanner", "nvidia": "skillspector"}
    executables = {}
    for name, program in programs.items():
        if installed.get(name) != pins["engines"][name]["version"]:
            raise ValueError("installed-version-mismatch")
        executable = state / "vendors" / name / ".venv" / ("Scripts" if os.name == "nt" else "bin") / (program + (".exe" if os.name == "nt" else ""))
        if not executable.is_file():
            raise ValueError("scanner-not-installed")
        executables[name] = executable
    return pins, executables


def scan_zip(archive: Path, state: Path, *, package_root: str | None = None) -> dict:
    pins, executables = read_state(state)
    started = dt.datetime.now(dt.timezone.utc).isoformat()
    with tempfile.TemporaryDirectory(prefix="shield-submission-") as directory:
        work = Path(directory)
        content = stage_archive(archive, work / "package", package_root=package_root)
        engines = [scan_engine(name, executable, "submitted-package", work / "package", work, pins["engines"][name])
                   for name, executable in executables.items()]
    complete = (len(engines) == 2 and {engine["engine"] for engine in engines} == {"cisco", "nvidia"}
                and all(engine["status"] in {"findings", "no-findings"}
                        and engine.get("coverage", {}).get("complete") is True for engine in engines))
    blocking = sum(f["severity"] in {"critical", "high"} for engine in engines for f in engine["findings"])
    return {"kind": "skillz-shield-package-report", "schema": 1,
            "started_at": started, "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "source": {"type": "zip", **content}, "toolchain": pins,
            "complete": complete, "high_or_critical_findings": blocking,
            "decision": "incomplete" if not complete else "review-required" if blocking else "pass",
            "engines": engines,
            "review_guidance": [{"engine": engine["engine"], "groups": review_groups(engine)[0],
                                 "truncated": review_groups(engine)[1]} for engine in engines]}


def render_html(report: dict) -> str:
    """Standalone readable evidence. Escape all values; no scripts or remote assets."""
    esc = lambda value: html.escape(str(value), quote=True)
    sections = []
    for engine in report["engines"]:
        name = engine["engine"]
        items = []
        diagnostics = engine.get("finding_diagnostics", {})
        groups, truncated = review_groups(engine)
        for guidance in groups:
            rule, severity = guidance["rule_id"], guidance["severity"]
            locations = guidance["locations"]
            location = "; ".join(locations) if locations else "File/line unavailable; inspect the package and upstream rule."
            items.append(f'<li><h3>{esc(rule)} · {esc(severity)} · {esc(guidance["count"])} finding(s)</h3><p>{esc(guidance["title"])}</p>'
                         f'<p><strong>Location:</strong> {esc(location)}</p><p><strong>Why review:</strong> {esc(guidance["why"])}</p>'
                         f'<p><strong>Suggested action:</strong> {esc(guidance["recommendation"])}</p>'
                         f'<p><a href="{esc(guidance["reference"])}" rel="noreferrer">Upstream rule reference</a></p></li>')
        coverage = esc(json.dumps(engine.get("coverage", {}), indent=2))
        errors = ", ".join(engine.get("errors", [])) or "None recorded"
        sections.append(f'<section><h2>{esc(name)} · {esc(engine["status"])}</h2>'
                        f'<p>Analysis errors: {esc(errors)}</p><ul>{"".join(items)}</ul>'
                        + (f'<p>Showing the first {MAX_REVIEW_GROUPS} rule/severity groups. Full findings remain in report.json.</p>' if truncated else '') +
                        f'<p>Location coverage: {esc(diagnostics.get("unavailable", 0))} unavailable; '
                        f'truncated: {esc(diagnostics.get("truncated", False))}.</p>'
                        f'<details><summary>Analysis coverage and reasons</summary><pre>{coverage}</pre></details></section>')
    source = report["source"]
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<meta name="referrer" content="no-referrer"><title>Skillz Shield package report</title>'
            '<style>body{max-width:70rem;margin:2rem auto;padding:0 1rem;background:#201712;color:#f5ead6;font:17px/1.6 system-ui}'
            'h1,h2,h3{line-height:1.25}a{color:#75d8cc}section{border-top:1px solid #89725c;padding:1rem 0}'
            'li{padding:1rem 0}pre{white-space:pre-wrap;overflow-wrap:anywhere}p{overflow-wrap:anywhere}</style></head><body>'
            f'<h1>Skillz Shield: {esc(report["decision"])}</h1>'
            '<p>This result covers static checks at the recorded time. It is not a safety or skill-quality certificate. '
            'Incomplete analysis is never a pass. Suggestions use the reviewed upstream revisions linked below; '
            'compare those with the scanner pins and review in context. Do not remove safeguards simply to silence a rule.</p>'
            f'<p>Completed: {esc(report["finished_at"])}. High/critical findings: {esc(report["high_or_critical_findings"])}.</p>'
            f'<p>Archive SHA-256: {esc(source["archive_sha256"])}<br>Package SHA-256: {esc(source["sha256"])}</p>'
            f'<p>Original files: {esc(source["files"])}. Original bytes: {esc(source["bytes"])}. '
            f'Temporary metadata wrapper generated: {esc(source["metadata_generated"])}.</p>'
            + "".join(sections)
            + '<details><summary>Exact scanner pins</summary><pre>'
            + esc(json.dumps(report["toolchain"], indent=2)) + '</pre></details></body></html>')


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan a whole skill ZIP using installed, pinned Cisco/NVIDIA engines.")
    parser.add_argument("archive", type=Path)
    parser.add_argument("--state", type=Path, required=True, help="Trusted directory produced by entrypoint.py resolve and install")
    parser.add_argument("--output", type=Path, required=True, help="New private directory for JSON and HTML results")
    parser.add_argument("--package-root", help="Explicit enclosing directory; files outside it are rejected")
    args = parser.parse_args()
    try:
        # No partial report or preexisting output can be mistaken for this scan.
        if args.output.exists():
            raise ValueError("output-already-exists")
        report = scan_zip(args.archive, args.state.resolve(), package_root=args.package_root)
        rendered = render_html(report)
        destination = args.output.absolute()
        _plain_path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        # Publish the complete pair in one rename, on the same filesystem.
        # The operator owns this private parent; uploaders never choose paths.
        with tempfile.TemporaryDirectory(prefix=".shield-report-", dir=destination.parent) as temporary:
            staged = Path(temporary) / "result"
            staged.mkdir()
            (staged / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            (staged / "report.html").write_text(rendered, encoding="utf-8")
            _plain_path(destination)
            if destination.exists():
                raise ValueError("output-already-exists")
            staged.rename(destination)
        print(f"Skillz Shield: {report['decision']}. JSON and HTML reports written.")
        return 0 if report["decision"] == "pass" else 1
    except (ValueError, OSError, KeyError, TypeError):
        print("Package scan or report delivery could not complete. No completed report bundle was issued. Check archive limits, installed scanner state, and output destination.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
