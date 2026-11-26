"""Deterministic offline tests for Stage 4 STIX 2.1 exporter, SOC Markdown report, and CLI."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import httpx
import respx
from typer.testing import CliRunner

from vtx_ti_enricher.main import app
from vtx_ti_enricher.markdown_report import render_markdown_report
from vtx_ti_enricher.models import EnrichBatchReport, EnrichedIOC, ProviderResult, ProviderStatus, Verdict
from vtx_ti_enricher.parser import classify_indicator
from vtx_ti_enricher.providers import AlienVaultOTXProvider, URLhausProvider
from vtx_ti_enricher.scoring import score_results
from vtx_ti_enricher.stix_exporter import (
    build_stix_pattern,
    escape_stix_pattern_value,
    export_stix_bundle,
)

_FIXED_TS = datetime(2026, 11, 26, 15, 30, 0, tzinfo=timezone.utc)


def _make_sample_report() -> EnrichBatchReport:
    ip_mal = classify_indicator("203.0.113.45", source="ALRT-001.src_ip")
    domain_sus = classify_indicator("evil-c2.example.com", source="ALRT-002.domain")
    ip_benign = classify_indicator("198.51.100.77", source="ALRT-003.src_ip")
    sha_mal = classify_indicator(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        source="ALRT-004.sha256",
    )
    assert ip_mal and domain_sus and ip_benign and sha_mal

    r_mal = [
        ProviderResult(
            provider="urlhaus",
            status=ProviderStatus.OK,
            malicious_score=95,
            detections=3,
            tags=["cobaltstrike"],
        ),
        ProviderResult(
            provider="otx",
            status=ProviderStatus.OK,
            malicious_score=85,
            detections=5,
            tags=["c2"],
        ),
    ]
    r_sus = [
        ProviderResult(
            provider="otx",
            status=ProviderStatus.OK,
            malicious_score=45,
            detections=2,
            tags=["phishing"],
        )
    ]
    r_benign = [
        ProviderResult(
            provider="otx",
            status=ProviderStatus.OK,
            malicious_score=0,
            detections=0,
        )
    ]
    r_sha = [
        ProviderResult(
            provider="urlhaus",
            status=ProviderStatus.OK,
            malicious_score=90,
            detections=2,
            tags=["dropper"],
        )
    ]

    items = [
        EnrichedIOC(ioc=ip_benign, provider_results=r_benign, assessment=score_results(r_benign)),
        EnrichedIOC(ioc=domain_sus, provider_results=r_sus, assessment=score_results(r_sus)),
        EnrichedIOC(ioc=ip_mal, provider_results=r_mal, assessment=score_results(r_mal)),
        EnrichedIOC(ioc=sha_mal, provider_results=r_sha, assessment=score_results(r_sha)),
    ]
    return EnrichBatchReport(
        input_source="samples/detection_lab_alerts.json",
        providers_enabled=["otx", "urlhaus"],
        total_enriched=len(items),
        skipped_internal=2,
        items=items,
    )


def test_stix_pattern_escaping_and_file_hash_mapping() -> None:
    assert escape_stix_pattern_value("a'b\\c") == "a\\'b\\\\c"

    url_ioc = classify_indicator("https://evil.example/path?q=it's")
    sha_ioc = classify_indicator("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert url_ioc is not None and sha_ioc is not None

    assert build_stix_pattern(url_ioc) == "[url:value = 'https://evil.example/path?q=it\\'s']"
    assert (
        build_stix_pattern(sha_ioc)
        == "[file:hashes.'SHA-256' = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']"
    )


def test_stix_bundle_is_deterministic_and_links_objects() -> None:
    report = _make_sample_report()

    bundle_a = export_stix_bundle(report, generated_at=_FIXED_TS)
    bundle_b = export_stix_bundle(report, generated_at=_FIXED_TS)

    assert bundle_a == bundle_b
    assert bundle_a["type"] == "bundle"
    assert str(bundle_a["id"]).startswith("bundle--")

    objects = bundle_a["objects"]
    ids = {str(obj["id"]) for obj in objects}
    assert len(ids) == len(objects)

    by_type: dict[str, list[dict[str, object]]] = {}
    for obj in objects:
        by_type.setdefault(str(obj["type"]), []).append(obj)

    assert len(by_type["identity"]) == 1
    assert len(by_type["indicator"]) == 4
    assert len(by_type["relationship"]) == 4
    assert len(by_type["sighting"]) == 4

    for rel in by_type["relationship"]:
        assert rel["relationship_type"] == "based-on"
        assert str(rel["source_ref"]) in ids
        assert str(rel["target_ref"]) in ids

    for sighting in by_type["sighting"]:
        assert str(sighting["sighting_of_ref"]) in ids
        assert sighting["where_sighted_refs"] == [by_type["identity"][0]["id"]]


def test_stix_bundle_min_verdict_filter() -> None:
    report = _make_sample_report()

    filtered = export_stix_bundle(
        report,
        min_verdict=Verdict.MALICIOUS,
        generated_at=_FIXED_TS,
    )
    indicators = [o for o in filtered["objects"] if o["type"] == "indicator"]
    assert len(indicators) == 2
    assert all(ind["x_vtx_verdict"] == "malicious" for ind in indicators)


def test_markdown_report_prioritizes_severity_and_defangs_by_default() -> None:
    report = _make_sample_report()

    md = render_markdown_report(report, defang_output=True, generated_at=_FIXED_TS)

    assert "# Threat Intelligence Enrichment Report" in md
    assert "| **MALICIOUS** | 2 |" in md
    assert "| **SUSPICIOUS** | 1 |" in md
    assert "| BENIGN | 1 |" in md
    assert "203[.]0[.]113[.]45" in md
    assert "198[.]51[.]100[.]77" in md
    assert "203.0.113.45" not in md
    assert md.index("203[.]0[.]113[.]45") < md.index("evil-c2[.]example[.]com")
    assert md.index("evil-c2[.]example[.]com") < md.index("198[.]51[.]100[.]77")


def test_markdown_report_escapes_pipe_characters_in_tables() -> None:
    ioc = classify_indicator("203.0.113.99", source="SRC|1")
    assert ioc is not None
    res = [
        ProviderResult(
            provider="otx",
            status=ProviderStatus.OK,
            malicious_score=50,
            tags=["tag|pipe"],
        )
    ]
    report = EnrichBatchReport(
        input_source="feed|source.txt",
        providers_enabled=["otx"],
        total_enriched=1,
        skipped_internal=0,
        items=[EnrichedIOC(ioc=ioc, provider_results=res, assessment=score_results(res))],
    )

    md = render_markdown_report(report, defang_output=True, generated_at=_FIXED_TS)
    assert "tag\\|pipe" in md
    assert "feed\\|source.txt" in md


def test_cli_enrich_exports_json_stix_and_markdown_offline(tmp_path: Path) -> None:
    sample_file = tmp_path / "iocs.txt"
    sample_file.write_text("203.0.113.45\n198.51.100.77\n", encoding="utf-8")

    json_out = tmp_path / "batch.json"
    stix_out = tmp_path / "bundle.stix.json"
    md_out = tmp_path / "report.md"
    cache_db = tmp_path / "cli_stage4.sqlite3"

    with respx.mock(assert_all_called=False) as router:
        router.get(url__startswith="https://otx.alienvault.com/api/v1/indicators/").mock(
            return_value=httpx.Response(
                200,
                json={"pulse_info": {"count": 4, "pulses": [{"tags": ["c2"]}]}},
            )
        )
        router.post(url__startswith="https://urlhaus-api.abuse.ch/v1/").mock(
            return_value=httpx.Response(200, json={"query_status": "no_results"})
        )

        runner = CliRunner()
        result = runner.invoke(
            app,
            [
                "enrich",
                str(sample_file),
                "--providers",
                "otx,urlhaus",
                "--cache-db",
                str(cache_db),
                "--output",
                str(json_out),
                "--stix-out",
                str(stix_out),
                "--md-out",
                str(md_out),
            ],
        )

    assert result.exit_code == 0, result.output
    assert json_out.exists()
    assert stix_out.exists()
    assert md_out.exists()
    assert '"type": "bundle"' in stix_out.read_text(encoding="utf-8")
    assert "# Threat Intelligence Enrichment Report" in md_out.read_text(encoding="utf-8")


def test_cli_export_subcommand_converts_existing_report(tmp_path: Path) -> None:
    report = _make_sample_report()
    report_file = tmp_path / "existing_report.json"
    report_file.write_text(report.model_dump_json(indent=2), encoding="utf-8")

    stix_out = tmp_path / "exported.stix.json"
    md_out = tmp_path / "exported.md"

    runner = CliRunner()
    res = runner.invoke(
        app,
        [
            "export",
            str(report_file),
            "--stix-out",
            str(stix_out),
            "--stix-min-verdict",
            "malicious",
            "--md-out",
            str(md_out),
        ],
    )

    assert res.exit_code == 0, res.output
    assert stix_out.exists()
    assert md_out.exists()
    stix_content = stix_out.read_text(encoding="utf-8")
    assert '"x_vtx_verdict": "malicious"' in stix_content
    assert '"x_vtx_verdict": "suspicious"' not in stix_content


def test_cli_export_rejects_when_no_output_flag_given(tmp_path: Path) -> None:
    report_file = tmp_path / "existing_report.json"
    report_file.write_text(_make_sample_report().model_dump_json(), encoding="utf-8")

    runner = CliRunner()
    res = runner.invoke(app, ["export", str(report_file)])
    assert res.exit_code == 2
    assert "at least one of --stix-out or --md-out" in res.output
