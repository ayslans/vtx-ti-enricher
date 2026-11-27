"""Typer CLI entrypoint for vtx-ti-enricher."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer
from pydantic import ValidationError

from vtx_ti_enricher import __version__
from vtx_ti_enricher.cache import AsyncSQLiteCache
from vtx_ti_enricher.engine import EnrichmentEngine
from vtx_ti_enricher.evidence_log import (
    append_report_to_evidence_log,
    verify_evidence_log,
)
from vtx_ti_enricher.markdown_report import write_markdown_report
from vtx_ti_enricher.models import EnrichBatchReport, Verdict
from vtx_ti_enricher.parser import parse_file
from vtx_ti_enricher.providers import build_providers
from vtx_ti_enricher.stix_exporter import write_stix_bundle

app = typer.Typer(
    help="vtx-ti-enricher — Asynchronous Threat Intelligence & IOC Enrichment CLI.",
    no_args_is_help=True,
)


@app.command()
def version() -> None:
    """Display package version."""
    typer.echo(f"vtx-ti-enricher {__version__}")


@app.command()
def parse(
    input_path: Path = typer.Argument(
        ...,
        exists=True,
        readable=True,
        help="Path to an IOC text list (.txt/.csv) or vtx-detection-lab alert JSON.",
    ),
    include_internal: bool = typer.Option(
        False,
        "--include-internal",
        help="Include RFC1918/private/local indicators instead of filtering for OPSEC.",
    ),
    defang_output: bool = typer.Option(
        True,
        "--defang/--no-defang",
        help="Display defanged indicators in terminal output.",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Optional path to export the structured ParseReport JSON.",
    ),
) -> None:
    """Extract, validate, normalize, deduplicate, and OPSEC-filter IOCs."""
    report = parse_file(input_path, include_internal=include_internal)

    typer.echo(f"Source: {report.input_source}")
    typer.echo(
        f"Candidates: {report.summary.total_candidates} | "
        f"Enrichable: {report.summary.unique_valid} | "
        f"Filtered Internal (OPSEC): {report.summary.skipped_internal} | "
        f"Invalid Ignored: {report.summary.invalid_ignored}"
    )

    if report.indicators:
        typer.echo("\nEnrichable Indicators:")
        for rec in report.indicators:
            shown = rec.defanged if defang_output else rec.value
            tag = " [RFC5737-LAB]" if rec.is_documentation else ""
            typer.echo(
                f"  - [{rec.ioc_type.value.upper():6}] {shown}{tag} (sources: {len(rec.sources)})"
            )

    if report.internal_indicators:
        typer.echo("\nFiltered Internal Indicators (OPSEC guard):")
        for rec in report.internal_indicators:
            shown = rec.defanged if defang_output else rec.value
            typer.echo(f"  - [{rec.ioc_type.value.upper():6}] {shown}")

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        typer.echo(f"\nReport exported to: {output}")


@app.command()
def enrich(
    input_path: Path = typer.Argument(
        ...,
        exists=True,
        readable=True,
        help="Path to an IOC text list (.txt/.csv) or vtx-detection-lab alert JSON.",
    ),
    providers: str = typer.Option(
        "abuseipdb,otx,urlhaus,virustotal",
        "--providers",
        "-p",
        help="Comma-separated list of Threat Intel providers.",
    ),
    concurrency: int = typer.Option(
        8,
        "--concurrency",
        "-c",
        min=1,
        max=64,
        help="Global maximum concurrent outbound provider lookups.",
    ),
    per_provider_concurrency: int = typer.Option(
        4,
        "--per-provider-concurrency",
        min=1,
        max=32,
        help="Maximum concurrent outbound requests per individual provider.",
    ),
    rate_limit: float = typer.Option(
        5.0,
        "--rate-limit",
        min=0.1,
        help="Per-provider token-bucket rate limit (requests/second).",
    ),
    queue_size: int = typer.Option(
        64,
        "--queue-size",
        min=1,
        max=1024,
        help="Bounded asyncio.Queue capacity for worker-pool backpressure.",
    ),
    timeout: float = typer.Option(
        10.0,
        "--timeout",
        min=1.0,
        help="HTTP request timeout in seconds.",
    ),
    cache_db: Path = typer.Option(
        Path(".vtx_ti_cache.sqlite3"),
        "--cache-db",
        help="Path to the local SQLite (WAL) cache database.",
    ),
    no_cache: bool = typer.Option(
        False,
        "--no-cache",
        help="Disable local SQLite cache for this run.",
    ),
    ttl: Optional[int] = typer.Option(
        None,
        "--ttl",
        min=1,
        help="Override TTL in seconds for all enabled providers.",
    ),
    include_internal: bool = typer.Option(
        False,
        "--include-internal",
        help="Override OPSEC guard and include RFC1918/internal indicators.",
    ),
    defang_output: bool = typer.Option(
        True,
        "--defang/--no-defang",
        help="Display defanged indicators in terminal and Markdown output.",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Optional path to export the EnrichBatchReport JSON.",
    ),
    stix_out: Optional[Path] = typer.Option(
        None,
        "--stix-out",
        help="Optional path to export a deterministic STIX 2.1 Bundle JSON.",
    ),
    stix_min_verdict: Optional[Verdict] = typer.Option(
        None,
        "--stix-min-verdict",
        case_sensitive=False,
        help="Minimum verdict to include in STIX 2.1 export (unknown|benign|suspicious|malicious).",
    ),
    md_out: Optional[Path] = typer.Option(
        None,
        "--md-out",
        help="Optional path to export an executive SOC Markdown report.",
    ),
    evidence_log: Optional[Path] = typer.Option(
        None,
        "--evidence-log",
        help="Optional path to append SHA-256 hash-chained evidence records (JSONL).",
    ),
    asset_id: Optional[str] = typer.Option(
        None,
        "--asset-id",
        help="Optional canonical asset_id recorded in the evidence ledger.",
    ),
) -> None:
    """Concurrently enrich parsed IOCs with WAL cache, circuit breakers, and verdict scoring."""
    provider_names = [name.strip() for name in providers.split(",") if name.strip()]
    try:
        provider_objs = build_providers(provider_names)
    except ValueError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    async def _run_enrich() -> EnrichBatchReport:
        if no_cache:
            engine = EnrichmentEngine(
                providers=provider_objs,
                cache=None,
                max_concurrency=concurrency,
                per_provider_concurrency=per_provider_concurrency,
                queue_maxsize=queue_size,
                timeout_seconds=timeout,
                rate_per_sec=rate_limit,
            )
            return await engine.enrich_file(input_path, include_internal=include_internal)

        provider_ttls = {p.name: ttl for p in provider_objs} if ttl is not None else None
        default_ttl = ttl if ttl is not None else 21600
        not_found_ttl = min(ttl, 900) if ttl is not None else 900

        async with AsyncSQLiteCache(
            db_path=cache_db,
            default_ttl_seconds=default_ttl,
            provider_ttls=provider_ttls,
            not_found_ttl_seconds=not_found_ttl,
        ) as cache:
            engine = EnrichmentEngine(
                providers=provider_objs,
                cache=cache,
                max_concurrency=concurrency,
                per_provider_concurrency=per_provider_concurrency,
                queue_maxsize=queue_size,
                timeout_seconds=timeout,
                rate_per_sec=rate_limit,
            )
            return await engine.enrich_file(input_path, include_internal=include_internal)

    report = asyncio.run(_run_enrich())

    typer.echo(f"Source: {report.input_source}")
    typer.echo(
        f"Providers: {', '.join(report.providers_enabled)} | "
        f"Enriched: {report.total_enriched} | "
        f"Filtered Internal (OPSEC): {report.skipped_internal}"
    )
    verdicts_txt = ", ".join(f"{k}={v}" for k, v in sorted(report.metrics.verdict_counts.items()))
    typer.echo(
        f"Metrics: duration={report.metrics.duration_ms:.1f}ms | "
        f"peak_inflight={report.metrics.peak_inflight}/{report.metrics.max_concurrency_limit} | "
        f"coalesced={report.metrics.coalesced_hits} | "
        f"cache_hits={report.metrics.cache_hits} | cache_misses={report.metrics.cache_misses}"
    )
    if verdicts_txt:
        typer.echo(f"Verdicts: {verdicts_txt}")

    for item in report.items:
        shown = item.ioc.defanged if defang_output else item.ioc.value
        header = f"\n[{item.ioc.ioc_type.value.upper()}] {shown}"
        if item.assessment is not None:
            a = item.assessment
            header += (
                f" -> {a.verdict.value.upper()} "
                f"(score={a.composite_score:.1f}, confidence={a.confidence.value})"
            )
        typer.echo(header)

        for res in item.provider_results:
            score_txt = f"score={res.malicious_score}" if res.malicious_score is not None else "score=n/a"
            cache_txt = " [CACHE]" if res.from_cache else ""
            err_txt = f" ({res.error})" if res.error else ""
            typer.echo(
                f"  - {res.provider:10} | {res.status.value:19} | {score_txt:9} | "
                f"att={res.attempts} | {res.latency_ms:.1f}ms{cache_txt}{err_txt}"
            )
        if item.assessment is not None:
            typer.echo(f"  Action: {item.assessment.recommended_action}")

    typer.echo("\nProvider Health:")
    for name, pm in report.metrics.providers.items():
        typer.echo(
            f"  - {name:10} | circuit={pm.circuit_state:9} | ok={pm.requests_ok} | "
            f"404={pm.not_found} | hit={pm.cache_hits} | miss={pm.cache_misses} | "
            f"skip={pm.skipped} | 429={pm.rate_limited} | err={pm.errors} | avg={pm.avg_latency_ms:.1f}ms"
        )

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        typer.echo(f"\nEnrichment report exported to: {output}")

    if stix_out:
        bundle = write_stix_bundle(report, stix_out, min_verdict=stix_min_verdict)
        typer.echo(
            f"STIX 2.1 bundle exported to: {stix_out} ({len(bundle['objects'])} objects)"
        )

    if md_out:
        write_markdown_report(report, md_out, defang_output=defang_output)
        typer.echo(f"Markdown SOC report exported to: {md_out}")

    if evidence_log:
        try:
            records = append_report_to_evidence_log(
                report,
                evidence_log,
                asset_id=asset_id,
            )
        except ValueError as exc:
            typer.echo(f"Error: {exc}", err=True)
            raise typer.Exit(code=1) from exc
        head = records[-1].entry_hash if records else "none"
        typer.echo(
            f"Evidence ledger updated: {evidence_log} (+{len(records)} entries, head={head})"
        )


@app.command()
def export(
    report_path: Path = typer.Argument(
        ...,
        exists=True,
        readable=True,
        help="Path to an existing EnrichBatchReport JSON file.",
    ),
    stix_out: Optional[Path] = typer.Option(
        None,
        "--stix-out",
        help="Output path for the deterministic STIX 2.1 Bundle JSON.",
    ),
    stix_min_verdict: Optional[Verdict] = typer.Option(
        None,
        "--stix-min-verdict",
        case_sensitive=False,
        help="Minimum verdict to include in STIX 2.1 export (unknown|benign|suspicious|malicious).",
    ),
    md_out: Optional[Path] = typer.Option(
        None,
        "--md-out",
        help="Output path for the executive SOC Markdown report.",
    ),
    evidence_log: Optional[Path] = typer.Option(
        None,
        "--evidence-log",
        help="Optional path to append SHA-256 hash-chained evidence records (JSONL).",
    ),
    asset_id: Optional[str] = typer.Option(
        None,
        "--asset-id",
        help="Optional canonical asset_id recorded in the evidence ledger.",
    ),
    defang_output: bool = typer.Option(
        True,
        "--defang/--no-defang",
        help="Defang indicators in the generated Markdown report.",
    ),
) -> None:
    """Convert an existing EnrichBatchReport JSON into STIX 2.1, Markdown SOC, and/or Evidence JSONL."""
    if stix_out is None and md_out is None and evidence_log is None:
        typer.echo(
            "Error: specify at least one of --stix-out, --md-out, or --evidence-log.",
            err=True,
        )
        raise typer.Exit(code=2)

    try:
        report = EnrichBatchReport.model_validate_json(
            report_path.read_text(encoding="utf-8")
        )
    except ValidationError as exc:
        typer.echo(f"Error: invalid EnrichBatchReport JSON: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    if stix_out:
        bundle = write_stix_bundle(report, stix_out, min_verdict=stix_min_verdict)
        typer.echo(
            f"STIX 2.1 bundle exported to: {stix_out} ({len(bundle['objects'])} objects)"
        )

    if md_out:
        write_markdown_report(report, md_out, defang_output=defang_output)
        typer.echo(f"Markdown SOC report exported to: {md_out}")

    if evidence_log:
        try:
            records = append_report_to_evidence_log(
                report,
                evidence_log,
                asset_id=asset_id,
            )
        except ValueError as exc:
            typer.echo(f"Error: {exc}", err=True)
            raise typer.Exit(code=1) from exc
        head = records[-1].entry_hash if records else "none"
        typer.echo(
            f"Evidence ledger updated: {evidence_log} (+{len(records)} entries, head={head})"
        )


@app.command("verify-evidence")
def verify_evidence(
    ledger_path: Path = typer.Argument(
        ...,
        exists=True,
        readable=True,
        help="Path to the SHA-256 hash-chained evidence JSONL ledger.",
    ),
) -> None:
    """Verify sequence continuity and SHA-256 hash chain integrity of an evidence ledger."""
    result = verify_evidence_log(ledger_path)
    if result.valid:
        head = result.head_hash or "empty"
        typer.echo(
            f"Evidence ledger VALID: {result.total_entries} entries verified (head={head})"
        )
        return

    typer.echo(
        f"Evidence ledger INVALID ({len(result.errors)} error(s)):",
        err=True,
    )
    for err in result.errors:
        typer.echo(f"  - {err}", err=True)
    raise typer.Exit(code=1)


@app.command("cache-stats")
def cache_stats(
    cache_db: Path = typer.Option(
        Path(".vtx_ti_cache.sqlite3"),
        "--cache-db",
        help="Path to the local SQLite (WAL) cache database.",
    ),
    purge: bool = typer.Option(
        False,
        "--purge",
        help="Purge expired cache entries before printing statistics.",
    ),
    clear: bool = typer.Option(
        False,
        "--clear",
        help="Clear all entries from the cache database.",
    ),
) -> None:
    """Inspect or maintain the local async SQLite Threat Intel cache."""
    if not cache_db.exists() and not purge and not clear:
        typer.echo(f"Cache database not found: {cache_db}")
        return

    async def _inspect() -> None:
        async with AsyncSQLiteCache(db_path=cache_db) as cache:
            if clear:
                removed = await cache.clear()
                typer.echo(f"Cleared {removed} cache entries.")
            elif purge:
                removed = await cache.purge_expired()
                typer.echo(f"Purged {removed} expired cache entries.")

            st = await cache.stats()
            typer.echo(f"Cache DB: {st.db_path} (journal_mode={st.journal_mode})")
            typer.echo(
                f"Entries: total={st.total_entries} | "
                f"active={st.active_entries} | expired={st.expired_entries}"
            )
            if st.by_provider:
                typer.echo("Active by Provider:")
                for prov, count in st.by_provider.items():
                    typer.echo(f"  - {prov:10}: {count}")

    asyncio.run(_inspect())


if __name__ == "__main__":
    app()
