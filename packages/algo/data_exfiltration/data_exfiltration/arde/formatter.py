"""Analyst-readable finding formatter.

Renders the machine-readable explanation into a stable, plain-text
report an analyst can read in a terminal or ticket. Every line comes
from the explanation structure — the formatter adds words, never
evidence.
"""

from __future__ import annotations

from typing import Any

from .explain import FindingExplanation

_WIDTH = 72


def format_finding_report(
    explanation: FindingExplanation,
    *,
    finding: Any = None,
    include_validation: bool = True,
) -> str:
    """Render an analyst-readable report from a FindingExplanation."""
    lines: list[str] = []
    add = lines.append

    title = "FINDING REPORT"
    if finding is not None:
        sev = getattr(finding, "severity", None)
        sev_text = getattr(sev, "value", sev) or "unrated"
        title = f"FINDING REPORT — severity: {str(sev_text).upper()}"
    add("=" * _WIDTH)
    add(title)
    add("=" * _WIDTH)
    add(f"finding:    {explanation.finding_id}")
    if explanation.session_id:
        add(f"session:    {explanation.session_id}")

    add("")
    add("WHAT HAPPENED")
    add("-" * _WIDTH)
    add(_wrap(explanation.what_happened, indent="  "))

    add("")
    add("WHY IT IS UNUSUAL")
    add("-" * _WIDTH)
    if explanation.why_unusual:
        for item in explanation.why_unusual:
            add(f"  - {_one_line(item)}")
    else:
        add("  (no elevated signals recorded)")

    add("")
    add("NORMAL BASELINE")
    add("-" * _WIDTH)
    bl = explanation.normal_baseline
    if bl.get("status") == "unavailable":
        add("  baseline unavailable")
    else:
        add(f"  scope:            {bl.get('baseline_scope')}")
        add(f"  quality:          {bl.get('baseline_quality')}")
        add(f"  cold start:       {bl.get('cold_start')}")
        if bl.get("volume_windows_evaluated"):
            add(f"  windows compared: {', '.join(bl['volume_windows_evaluated'])}")

    add("")
    add("WHAT CHANGED")
    add("-" * _WIDTH)
    if explanation.what_changed:
        for item in explanation.what_changed:
            add(f"  - {item}")
    else:
        add("  (nothing measurably changed vs history)")

    add("")
    add("DATA INVOLVED")
    add("-" * _WIDTH)
    di = explanation.data_involved
    if di.get("resources"):
        add(f"  resources:        {', '.join(di['resources'])}")
    add(f"  objects:          {di.get('objects_accessed')}")
    add(f"  bytes:            {_fmt_bytes(di.get('bytes_total'))} ({di.get('bytes_presence')})")
    add(f"  requests:         {di.get('request_count')}")

    add("")
    add("SENSITIVITY")
    add("-" * _WIDTH)
    sens = explanation.sensitivity
    if sens.get("score") is None:
        add("  no sensitivity enrichment available")
    else:
        add(f"  score:            {sens.get('score')}")
        add(f"  source:           {sens.get('source')}")

    add("")
    add("DATA MOVEMENT")
    add("-" * _WIDTH)
    mv = explanation.data_movement
    dests = mv.get("unique_destinations") or []
    add(f"  destinations:     {', '.join(dests) if dests else '(none observed)'}")
    add(f"  egress bytes:     {_fmt_bytes(mv.get('network_egress_bytes'))}")
    if mv.get("egress_ratio") is not None:
        add(f"  egress ratio:     {mv.get('egress_ratio')}")
    if mv.get("unique_countries"):
        add(f"  countries:        {', '.join(mv['unique_countries'])}")

    add("")
    add("TOP CONTRIBUTORS")
    add("-" * _WIDTH)
    if explanation.top_contributors:
        for item in explanation.top_contributors:
            add(f"  - {item}")
    else:
        add("  (no weighted contributions recorded)")

    add("")
    add("SUPPORTING EVIDENCE")
    add("-" * _WIDTH)
    for item in explanation.supporting_evidence:
        add(f"  + [{item.get('kind')}] {_one_line(item.get('value'))}")
    if not explanation.supporting_evidence:
        add("  (none)")

    add("")
    add("CONTRADICTING EVIDENCE")
    add("-" * _WIDTH)
    for item in explanation.contradicting_evidence:
        note = item.get("note") or ""
        add(f"  - [{item.get('kind')}] {_one_line(item.get('value'))}")
        if note:
            add(f"      {_wrap(note, indent='      ')}")
    if not explanation.contradicting_evidence:
        add("  (none)")

    add("")
    add("UNAVAILABLE TELEMETRY")
    add("-" * _WIDTH)
    if explanation.unavailable_telemetry:
        for item in explanation.unavailable_telemetry:
            add(f"  ! {item}")
    else:
        add("  (all expected telemetry was present)")

    add("")
    add("TRUST GRADES")
    add("-" * _WIDTH)
    add(f"  baseline quality:     {explanation.baseline_quality}")
    add(f"  feature availability: {explanation.feature_availability}")
    add(f"  model agreement:      {explanation.model_agreement}")

    if include_validation and explanation.validation:
        v = explanation.validation
        add("")
        add("ARDE VALIDATION")
        add("-" * _WIDTH)
        add(f"  status:           {v.get('validation_status')}")
        add(f"  robustness:       {v.get('robustness_score')} ({v.get('robustness_level')})")
        if v.get("failed_checks"):
            add(f"  failed checks:    {', '.join(v['failed_checks'])}")
        if v.get("warning_checks"):
            add(f"  warning checks:   {', '.join(v['warning_checks'])}")
        matched = [
            e for e in (v.get("exceptions_applied") or []) if e.get("matched")
        ]
        if matched:
            for e in matched:
                add(f"  exception:        {e.get('profile_name')} ({e.get('kind')}) — {e.get('reason')}")
        if v.get("downgrade"):
            d = v["downgrade"]
            add(f"  severity change:  {d.get('from')} -> {d.get('to')} ({d.get('reason')})")

    add("")
    add(
        "NOTE: sensitivity comes only from external enrichment; this report "
        "describes evidence, it does not remediate. Remediation belongs to "
        "the Aegivion remediation layer."
    )
    add("=" * _WIDTH)
    return "\n".join(lines)


# ----------------------------------------------------------------------


def _one_line(value: Any) -> str:
    if isinstance(value, list):
        return ", ".join(str(v) for v in value) if value else "(empty)"
    return str(value)


def _wrap(text: str, indent: str = "", width: int = _WIDTH) -> str:
    import textwrap

    return textwrap.fill(str(text), width=width, initial_indent=indent, subsequent_indent=indent)


def _fmt_bytes(value: Any) -> str:
    if value is None:
        return "unavailable"
    try:
        n = float(value)
    except (TypeError, ValueError):
        return str(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024.0 or unit == "TB":
            return f"{n:,.1f} {unit}"
        n /= 1024.0
    return f"{n:,.1f} TB"
