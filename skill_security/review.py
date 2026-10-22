"""Exact-content, time-bounded human review of known scanner limitations.

This never changes a vendor result or the raw scan decision. A consumer may use
the separate review decision as its merge policy after protecting its review
ledger from unreviewed edits.
"""

from collections import Counter
import datetime as dt
import re

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_PATH = re.compile(r"(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\Z")
_BLOCKING = {"critical", "high"}
_REVIEWABLE_NVIDIA_REASONS = {"reference_missing"}


def _sha(value):
    return isinstance(value, str) and bool(_SHA.fullmatch(value))


def _finding_rows(engine):
    """Return an exact multiset of located high/critical findings, or None."""
    findings = [f for f in engine.get("findings", []) if f.get("severity") in _BLOCKING]
    locations = [f for f in engine.get("finding_diagnostics", {}).get("locations", [])
                 if f.get("severity") in _BLOCKING]
    if (len(findings) != len(locations) or engine.get("finding_diagnostics", {}).get("unavailable")
            or engine.get("finding_diagnostics", {}).get("truncated")):
        return None
    if Counter((f.get("rule_id"), f.get("severity")) for f in findings) != Counter(
            (f.get("rule_id"), f.get("severity")) for f in locations):
        return None
    rows = []
    for row in locations:
        if not isinstance(row.get("rule_id"), str) or not _PATH.fullmatch(str(row.get("file", ""))):
            return None
        if not isinstance(row.get("line"), int) or row["line"] < 1:
            return None
        rows.append((engine["engine"], row["rule_id"], row["severity"], row["file"], row["line"]))
    return Counter(rows)


def _coverage_rows(engine):
    """Admit only fully inspected NVIDIA reference-resolution exceptions."""
    if engine["status"] != "incomplete":
        return Counter()
    if engine["engine"] != "nvidia" or engine.get("errors") != ["analysis_incomplete"]:
        return None
    coverage = engine.get("coverage", {})
    if (coverage.get("complete") is not False or coverage.get("execution_successful") is not True
            or coverage.get("coverage_percent") != 100.0
            or coverage.get("total_components") != coverage.get("scanned_components")
            or coverage.get("fully_inspected_files") != coverage.get("total_components")
            or coverage.get("partially_inspected_files") != 0
            or coverage.get("entirely_uninspected_files") != 0
            or coverage.get("ledger_fatal_count") != 0
            or coverage.get("exclusion_count") != 0 or coverage.get("limitation_count") != 0
            or coverage.get("analyzer_details_truncated") is not False
            or not coverage.get("analyzer_details")
            or set(coverage.get("incomplete_reasons", [])) != {"ledger_exceptions", "vendor_declared_incomplete"}):
        return None
    reasons = coverage.get("ledger_reason_counts", {})
    if not isinstance(reasons, dict) or not reasons or set(reasons) - _REVIEWABLE_NVIDIA_REASONS:
        return None
    if any(a.get("status") not in {"completed", "not_applicable", "disabled"}
           or any(a.get(k) != 0 for k in ("partial", "skipped", "failed", "unaccounted"))
           for a in coverage.get("analyzer_details", [])):
        return None
    diagnostics = engine.get("coverage_diagnostics", {})
    locations = diagnostics.get("locations", [])
    if (diagnostics.get("unavailable") or diagnostics.get("truncated")
            or len(locations) != coverage.get("ledger_exception_count")
            or len(locations) != sum(reasons.values())):
        return None
    rows = []
    for row in locations:
        reason = row.get("reason_code")
        if (reason not in _REVIEWABLE_NVIDIA_REASONS
                or not _PATH.fullmatch(str(row.get("file", "")))
                or not isinstance(row.get("line"), int) or row["line"] < 1):
            return None
        rows.append((engine["engine"], reason, row["file"], row["line"]))
    if Counter(row[1] for row in rows) != Counter(reasons):
        return None
    return Counter(rows)


def _ledger_rows(rows, fields):
    if not isinstance(rows, list):
        return None
    try:
        values = [tuple(row[field] for field in fields) for row in rows]
    except (KeyError, TypeError):
        return None
    if any(not isinstance(value[-1], int) or value[-1] < 1 for value in values):
        return None
    return Counter(values)


def evaluate(report, ledger, today=None):
    """Return separate policy evidence; never mutate the raw report."""
    today = today or dt.datetime.now(dt.timezone.utc).date()
    denied = {"decision": "review-required", "reason": "unmatched-or-unreviewable-evidence", "reviewed_packages": 0}
    if report.get("decision") == "pass" and report.get("complete") is True:
        return {"decision": "raw-pass", "reason": "vendor-analysis-passed", "reviewed_packages": 0}
    if (report.get("decision") not in {"incomplete", "review-required"}
            or not isinstance(ledger, dict) or ledger.get("schema") != 1
            or not isinstance(ledger.get("reviews"), list)
            or not _sha(report.get("toolchain", {}).get("fingerprint"))):
        return denied
    reviews = ledger["reviews"]
    if len(reviews) > 512 or any(not isinstance(r, dict) for r in reviews):
        return denied
    by_package = {r.get("package"): r for r in reviews}
    if len(by_package) != len(reviews):
        return denied
    reviewed = 0
    found_critical = 0
    found_incomplete = False
    for package in report.get("packages", []):
        engines = package.get("engines", [])
        if len(engines) != 2 or {e.get("engine") for e in engines} != {"cisco", "nvidia"}:
            return denied
        found_critical += sum(f.get("severity") in _BLOCKING for e in engines for f in e.get("findings", []))
        found_incomplete |= any(e.get("status") == "incomplete" for e in engines)
        blocking = any(e.get("status") == "incomplete" or any(
            f.get("severity") in _BLOCKING for f in e.get("findings", [])) for e in engines)
        if not blocking:
            continue
        record = by_package.get(package.get("package"))
        if (not record or not _sha(record.get("content_sha256"))
                or package.get("content", {}).get("metadata_generated") is not False):
            return denied
        try:
            expiry = dt.date.fromisoformat(record["expires"])
        except (KeyError, TypeError, ValueError):
            return denied
        if (expiry < today or expiry > today + dt.timedelta(days=90)
                or record["content_sha256"] != package.get("content", {}).get("sha256")
                or record.get("toolchain_fingerprint") != report["toolchain"]["fingerprint"]
                or not isinstance(record.get("reviewer"), str) or not record["reviewer"].strip()
                or not isinstance(record.get("rationale"), str) or len(record["rationale"].strip()) < 20):
            return denied
        findings = Counter()
        coverage = Counter()
        for engine in engines:
            one_findings = _finding_rows(engine)
            one_coverage = _coverage_rows(engine)
            if one_findings is None or one_coverage is None:
                return denied
            findings += one_findings
            coverage += one_coverage
        if findings != _ledger_rows(record.get("findings"), ("engine", "rule_id", "severity", "file", "line")):
            return denied
        if coverage != _ledger_rows(record.get("coverage_gaps"), ("engine", "reason_code", "file", "line")):
            return denied
        reviewed += 1
    if (not reviewed or report.get("expected_packages") != len(report.get("packages", []))
            or report.get("high_or_critical_findings") != found_critical
            or report.get("decision") != ("incomplete" if found_incomplete else "review-required")):
        return denied
    return {"decision": "reviewed-limitation", "reason": "exact-evidence-reviewed", "reviewed_packages": reviewed}
