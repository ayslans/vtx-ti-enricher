"""Executive SOC Markdown report generator with defanged output and prioritized triage."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from vtx_ti_enricher import __version__
from vtx_ti_enricher.models import (
    EnrichBatchReport,
    EnrichedIOC,
    Verdict,
    VerdictAssessment,
)
from vtx_ti_enricher.scoring import score_results

_VERDICT_PRIORITY: dict[Verdict, int] = {
    Verdict.MALICIOUS: 3,
    Verdict.SUSPICIOUS: 2,
    Verdict.BENIGN: 1,
    Verdict.UNKNOWN: 0,
}

_VERDICT_BADGE: dict[Verdict, str] = {
    Verdict.MALICIOUS: "**MALICIOUS**",
    Verdict.SUSPICIOUS: "**SUSPICIOUS**",
    Verdict.BENIGN: "BENIGN",
    Verdict.UNKNOWN: "UNKNOWN",
}


def _escape_md(text: str) -> str:
    """Escape pipes and newlines to keep Markdown tables structurally valid."""
    return text.replace("|", "\\|").replace("\r", " ").replace("\n", " ").strip()


def _resolve_assessment(item: EnrichedIOC) -> VerdictAssessment:
    if item.assessment is not None:
        return item.assessment
    return score_results(item.provider_results)


def render_markdown_report(
    report: EnrichBatchReport,
    defang_output: bool = True,
    generated_at: datetime | None = None,
) -> str:
    """Render an EnrichBatchReport into an executive SOC Markdown document."""
    ts = (
        generated_at.astimezone(timezone.utc)
        if generated_at is not None
        else datetime.now(timezone.utc)
    )
    ts_str = ts.strftime("%Y-%m-%d %H:%M:%S UTC")

    assessed_items: list[tuple[EnrichedIOC, VerdictAssessment]] = [
        (item, _resolve_assessment(item)) for item in report.items
    ]
    assessed_items.sort(
        key=lambda pair: (
            -_VERDICT_PRIORITY[pair[1].verdict],
            -pair[1].composite_score,
            pair[0].ioc.ioc_type.value,
            pair[0].ioc.value,
        )
    )

    counts: dict[Verdict, int] = {v: 0 for v in Verdict}
    for _, assessment in assessed_items:
        counts[assessment.verdict] += 1

    m = report.metrics
    lines: list[str] = [
        "# Threat Intelligence Enrichment Report",
        "",
        f"* **Generated:** {ts_str} (`vtx-ti-enricher v{__version__}`)",
        f"* **Input Source:** `{_escape_md(report.input_source)}`",
        f"* **Providers Enabled:** {', '.join(report.providers_enabled) if report.providers_enabled else 'none'}",
        f"* **Enriched Indicators:** {report.total_enriched} | **Filtered Internal (OPSEC):** {report.skipped_internal}",
        (
            f"* **Execution Telemetry:** duration=`{m.duration_ms:.1f}ms` | "
            f"peak_inflight=`{m.peak_inflight}/{m.max_concurrency_limit}` | "
            f"coalesced=`{m.coalesced_hits}` | cache_hits=`{m.cache_hits}` | "
            f"cache_misses=`{m.cache_misses}`"
        ),
        "",
        "## Executive Summary",
        "",
        "| Verdict | Count |",
        "| :--- | :---: |",
        f"| {_VERDICT_BADGE[Verdict.MALICIOUS]} | {counts[Verdict.MALICIOUS]} |",
        f"| {_VERDICT_BADGE[Verdict.SUSPICIOUS]} | {counts[Verdict.SUSPICIOUS]} |",
        f"| {_VERDICT_BADGE[Verdict.BENIGN]} | {counts[Verdict.BENIGN]} |",
        f"| {_VERDICT_BADGE[Verdict.UNKNOWN]} | {counts[Verdict.UNKNOWN]} |",
        "",
        "## Prioritized Triage Queue",
        "",
    ]

    if not assessed_items:
        lines.append("_No enrichable indicators found in this batch._")
        lines.append("")
    else:
        lines.extend(
            [
                "| Type | Indicator | Verdict | Score | Confidence | Corroborated | Tags | Recommended Action |",
                "| :--- | :--- | :--- | :---: | :---: | :---: | :--- | :--- |",
            ]
        )
        for item, a in assessed_items:
            shown = item.ioc.defanged if defang_output else item.ioc.value
            tags_txt = ", ".join(a.tags[:5]) if a.tags else "-"
            corr_txt = "Yes" if a.corroborated else "No"
            lines.append(
                f"| `{item.ioc.ioc_type.value.upper()}` | `{_escape_md(shown)}` | "
                f"{_VERDICT_BADGE[a.verdict]} | {a.composite_score:.1f} | "
                f"{a.confidence.value.upper()} | {corr_txt} | "
                f"{_escape_md(tags_txt)} | {_escape_md(a.recommended_action)} |"
            )
        lines.append("")

    if assessed_items:
        lines.extend(["## Detailed Evidence & Reasoning", ""])
        for item, a in assessed_items:
            shown = item.ioc.defanged if defang_output else item.ioc.value
            lines.append(
                f"### [{item.ioc.ioc_type.value.upper()}] `{shown}` — "
                f"{a.verdict.value.upper()} ({a.composite_score:.1f}/100, {a.confidence.value})"
            )
            lines.append("")
            if item.ioc.sources:
                lines.append(f"* **Sources:** {', '.join(f'`{s}`' for s in item.ioc.sources)}")
            lines.append(f"* **Action:** {a.recommended_action}")
            if a.reasons:
                lines.append("* **Reasoning:**")
                for reason in a.reasons:
                    lines.append(f"  * {reason}")
            if item.provider_results:
                lines.extend(
                    [
                        "",
                        "| Provider | Status | Score | Detections | Attempts | Cache | Latency (ms) |",
                        "| :--- | :--- | :---: | :---: | :---: | :---: | :---: |",
                    ]
                )
                for res in item.provider_results:
                    score_txt = str(res.malicious_score) if res.malicious_score is not None else "n/a"
                    det_txt = (
                        f"{res.detections}/{res.total_engines}"
                        if res.total_engines > 0
                        else str(res.detections)
                    )
                    cache_txt = "HIT" if res.from_cache else "MISS"
                    lines.append(
                        f"| {res.provider} | `{res.status.value}` | {score_txt} | "
                        f"{det_txt} | {res.attempts} | {cache_txt} | {res.latency_ms:.1f} |"
                    )
            lines.append("")

    if m.providers:
        lines.extend(
            [
                "## Provider Health & Telemetry",
                "",
                "| Provider | Circuit | OK | 404 | Cache Hit | Cache Miss | Skipped | 429 | Errors | Avg Latency (ms) |",
                "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
            ]
        )
        for name in sorted(m.providers.keys()):
            pm = m.providers[name]
            lines.append(
                f"| {name} | `{pm.circuit_state}` | {pm.requests_ok} | {pm.not_found} | "
                f"{pm.cache_hits} | {pm.cache_misses} | {pm.skipped} | "
                f"{pm.rate_limited} | {pm.errors} | {pm.avg_latency_ms:.1f} |"
            )
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def write_markdown_report(
    report: EnrichBatchReport,
    output_path: Path,
    defang_output: bool = True,
    generated_at: datetime | None = None,
) -> str:
    """Render and write the executive SOC Markdown report to disk as UTF-8."""
    content = render_markdown_report(
        report=report,
        defang_output=defang_output,
        generated_at=generated_at,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")
    return content
