import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from vtx_ti_enricher.evidence_log import (
    GENESIS_PREV_HASH,
    UNKNOWN_ASSET_ID,
    append_report_to_evidence_log,
    normalize_asset_id,
    verify_evidence_log,
)
from vtx_ti_enricher.main import app
from vtx_ti_enricher.models import (
    ConfidenceLevel,
    EnrichBatchReport,
    EnrichedIOC,
    IOCRecord,
    IOCType,
    ProviderResult,
    ProviderStatus,
    Verdict,
    VerdictAssessment,
)

runner = CliRunner()


def _sample_report(indicators: list[tuple[str, str, Verdict, float]]) -> EnrichBatchReport:
    items: list[EnrichedIOC] = []
    for raw_val, defanged_val, verdict, score in indicators:
        items.append(
            EnrichedIOC(
                ioc=IOCRecord(
                    ioc_type=IOCType.IPV4,
                    value=raw_val,
                    defanged=defanged_val,
                    is_documentation=True,
                    sources=["sample_alerts.json"],
                ),
                provider_results=[
                    ProviderResult(
                        provider="virustotal",
                        status=ProviderStatus.OK,
                        malicious_score=int(score),
                        detections=8 if verdict == Verdict.MALICIOUS else 1,
                        total_engines=70,
                    ),
                    ProviderResult(
                        provider="abuseipdb",
                        status=ProviderStatus.OK,
                        malicious_score=int(score),
                    ),
                ],
                assessment=VerdictAssessment(
                    verdict=verdict,
                    composite_score=score,
                    confidence=ConfidenceLevel.HIGH,
                    responding_providers=2,
                    malicious_providers=2 if verdict == Verdict.MALICIOUS else 0,
                    corroborated=verdict == Verdict.MALICIOUS,
                    recommended_action="Block indicator at perimeter.",
                ),
            )
        )
    return EnrichBatchReport(
        input_source="sample_alerts.json",
        providers_enabled=["abuseipdb", "virustotal"],
        total_enriched=len(items),
        skipped_internal=0,
        items=items,
    )


def test_append_and_verify_hash_chain_across_batches(tmp_path: Path) -> None:
    ledger = tmp_path / "evidence_ledger.jsonl"

    batch1 = _sample_report(
        [
            ("203.0.113.42", "203[.]0[.]113[.]42", Verdict.MALICIOUS, 90.0),
            ("198.51.100.7", "198[.]51[.]100[.]7", Verdict.SUSPICIOUS, 45.0),
        ]
    )
    batch2 = _sample_report(
        [
            ("192.0.2.15", "192[.]0[.]2[.]15", Verdict.BENIGN, 0.0),
        ]
    )

    recs1 = append_report_to_evidence_log(batch1, ledger, asset_id="PAY-LNX-GW-01")
    recs2 = append_report_to_evidence_log(batch2, ledger, asset_id="cde-app-win-01")

    assert len(recs1) == 2
    assert len(recs2) == 1
    assert recs1[0].seq == 1
    assert recs1[0].prev_hash == GENESIS_PREV_HASH
    assert recs1[0].asset_id == "pay-lnx-gw-01"
    assert recs1[0].providers == ["abuseipdb", "virustotal"]

    assert recs1[1].seq == 2
    assert recs1[1].prev_hash == recs1[0].entry_hash

    assert recs2[0].seq == 3
    assert recs2[0].prev_hash == recs1[1].entry_hash
    assert recs2[0].asset_id == "cde-app-win-01"

    check = verify_evidence_log(ledger)
    assert check.valid is True
    assert check.total_entries == 3
    assert check.head_hash == recs2[0].entry_hash
    assert check.errors == []


def test_verify_detects_tampered_field_and_deleted_line(tmp_path: Path) -> None:
    ledger = tmp_path / "tampered.jsonl"
    report = _sample_report(
        [
            ("203.0.113.42", "203[.]0[.]113[.]42", Verdict.MALICIOUS, 90.0),
            ("198.51.100.7", "198[.]51[.]100[.]7", Verdict.SUSPICIOUS, 45.0),
            ("192.0.2.15", "192[.]0[.]2[.]15", Verdict.BENIGN, 0.0),
        ]
    )
    append_report_to_evidence_log(report, ledger, asset_id="pay-lnx-gw-01")

    # 1) Adultera o veredito da primeira linha sem recalcular entry_hash
    lines = ledger.read_text(encoding="utf-8").splitlines()
    first = json.loads(lines[0])
    first["verdict"] = "benign"
    tampered_field = tmp_path / "tampered_field.jsonl"
    tampered_field.write_text(
        "\n".join([json.dumps(first), lines[1], lines[2]]) + "\n",
        encoding="utf-8",
    )
    res_field = verify_evidence_log(tampered_field)
    assert res_field.valid is False
    assert any("entry_hash mismatch" in err for err in res_field.errors)

    # 2) Remove linha intermediária quebrando sequência e prev_hash
    deleted_line = tmp_path / "deleted_line.jsonl"
    deleted_line.write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")
    res_del = verify_evidence_log(deleted_line)
    assert res_del.valid is False
    assert any("sequence mismatch" in err for err in res_del.errors)
    assert any("prev_hash mismatch" in err for err in res_del.errors)


def test_append_refuses_corrupted_ledger_and_normalizes_asset_id(tmp_path: Path) -> None:
    assert normalize_asset_id("PAY-LNX-GW-01") == "pay-lnx-gw-01"
    assert normalize_asset_id("INVALID ASSET!") == UNKNOWN_ASSET_ID
    assert normalize_asset_id(None) == UNKNOWN_ASSET_ID

    ledger = tmp_path / "corrupted.jsonl"
    ledger.write_text('{"corrupt": true}\n', encoding="utf-8")

    report = _sample_report([("203.0.113.42", "203[.]0[.]113[.]42", Verdict.MALICIOUS, 90.0)])
    with pytest.raises(ValueError, match="Refusing to append to corrupted evidence ledger"):
        append_report_to_evidence_log(report, ledger, asset_id="pay-lnx-gw-01")


def test_cli_export_and_verify_evidence(tmp_path: Path) -> None:
    report_path = tmp_path / "enrich_report.json"
    ledger_path = tmp_path / "evidence.jsonl"

    report = _sample_report([("203.0.113.42", "203[.]0[.]113[.]42", Verdict.MALICIOUS, 90.0)])
    report_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")

    exp_res = runner.invoke(
        app,
        [
            "export",
            str(report_path),
            "--evidence-log",
            str(ledger_path),
            "--asset-id",
            "pay-lnx-gw-01",
        ],
    )
    assert exp_res.exit_code == 0, exp_res.output
    assert ledger_path.exists()

    ver_ok = runner.invoke(app, ["verify-evidence", str(ledger_path)])
    assert ver_ok.exit_code == 0, ver_ok.output
    assert "VALID" in ver_ok.output

    # Corrompe o arquivo e valida exit code 1
    obj = json.loads(ledger_path.read_text(encoding="utf-8").strip())
    obj["verdict"] = "benign"
    ledger_path.write_text(json.dumps(obj) + "\n", encoding="utf-8")

    ver_fail = runner.invoke(app, ["verify-evidence", str(ledger_path)])
    assert ver_fail.exit_code == 1
    assert "INVALID" in ver_fail.output
