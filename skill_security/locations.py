"""Optional file/line diagnostics, never verdicts or arbitrary scanner text."""
import re
from pathlib import Path

_SAFE = re.compile(r"[A-Za-z0-9_./+ -]{1,512}\Z")
_LIMIT = 1000


def inventory(staged: Path) -> dict[str, tuple[str, int]]:
    """Capture trusted staged identities before invoking either scanner."""
    result = {}
    for path in staged.rglob("*"):
        if path.is_symlink() or not path.is_file():
            continue
        relative = path.relative_to(staged).as_posix()
        if not _SAFE.fullmatch(relative):
            continue
        data = path.read_bytes()
        lines = data.count(b"\n") + bool(data and not data.endswith(b"\n"))
        item = (relative, lines)
        result[relative] = item
        result[path.as_posix()] = item
    return result


def diagnostics(name: str, report: dict, normalized: dict, files: dict) -> dict:
    """Allow only normalized rules and known file identities with in-file lines.

    NVIDIA shape: Finding.to_dict at 091a509b3d6ba8ff5be528966e1f43c2e68cf214.
    Unknown, malformed, transitive and unbound locations remain unavailable.
    No report-owned path is opened and no message/snippet is emitted.
    """
    output = {"locations": [], "unavailable": 0, "truncated": False}
    if not normalized.get("coverage", {}).get("package_path_bound"):
        return output
    allowed = {(f["rule_id"], f["severity"]) for f in normalized["findings"]}
    records = report.get("issues" if name == "nvidia" else "findings", [])
    if not isinstance(records, list):
        return output
    seen = set()
    examined = 0
    for finding in records:
        if not isinstance(finding, dict):
            continue
        rule = finding.get("id" if name == "nvidia" else "rule_id")
        severity = finding.get("severity")
        if not isinstance(rule, str) or not isinstance(severity, str) or (rule, severity.lower()) not in allowed:
            continue
        if name == "nvidia":
            candidates = finding.get("occurrences") or [finding.get("location")]
        else:
            candidates = [{"file": finding.get("file_path"), "start_line": finding.get("line_number")}]
        if not isinstance(candidates, list):
            output["unavailable"] += 1
            continue
        for candidate in candidates:
            examined += 1
            if examined > _LIMIT:
                output["truncated"] = True
                return output
            if not isinstance(candidate, dict) or any(
                source.get(key) for source in (finding, candidate)
                for key in ("source_identity", "source_digest", "source_url", "transitive_depth")
            ):
                output["unavailable"] += 1
                continue
            path, line = candidate.get("file"), candidate.get("start_line")
            item = files.get(path.replace("\\", "/")) if isinstance(path, str) else None
            if item is None or type(line) is not int or not 1 <= line <= item[1]:
                output["unavailable"] += 1
                continue
            key = (rule, severity.lower(), item[0], line)
            if key not in seen:
                seen.add(key)
                output["locations"].append(dict(zip(("rule_id", "severity", "file", "line"), key)))
    return output


def coverage_diagnostics(report: dict, normalized: dict, files: dict) -> dict:
    """Locate known NVIDIA ledger reasons at their bundled source origins.

    The vendor's build_context reference_resolution events use the primary
    source path and reference line. Never retain reference targets or messages.
    Reason codes must already exist in the normalized allowlisted counters.
    """
    output = {"locations": [], "unavailable": 0, "truncated": False}
    coverage = normalized.get("coverage", {})
    if not coverage.get("package_path_bound"):
        return output
    completeness = report.get("analysis_completeness")
    if not isinstance(completeness, dict):
        return output
    rows = completeness.get("ledger_exceptions")
    if not isinstance(rows, list):
        return output
    reasons = set(coverage.get("ledger_reason_counts", {})) - {"unknown"}
    seen = {}
    for row in rows[:_LIMIT]:
        if not isinstance(row, dict):
            output["unavailable"] += 1
            continue
        reason, path, line = row.get("reason_code"), row.get("path"), row.get("start_line")
        item = files.get(path.replace("\\", "/")) if isinstance(path, str) else None
        if (not isinstance(reason, str) or reason not in reasons or item is None
                or type(line) is not int or not 1 <= line <= item[1]
                or any(row.get(key) for key in ("source_identity", "source_digest", "source_url", "transitive_depth"))):
            output["unavailable"] += 1
            continue
        key = (reason, item[0], line)
        if key in seen:
            output["locations"][seen[key]]["occurrences"] += 1
        else:
            seen[key] = len(output["locations"])
            output["locations"].append({**dict(zip(("reason_code", "file", "line"), key)),
                                        "occurrences": 1})
    output["truncated"] = len(rows) > _LIMIT
    return output
