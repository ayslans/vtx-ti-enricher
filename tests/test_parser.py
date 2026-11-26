"""Unit tests for Stage 1 IOC parsing, refanging, defanging, and OPSEC guardrails."""

from pathlib import Path
from vtx_ti_enricher.models import IOCType
from vtx_ti_enricher.parser import classify_indicator, defang, parse_file, refang

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"


def test_refang_and_defang_roundtrip() -> None:
    assert refang("hxxps://evil[.]example[.]com/a") == "https://evil.example.com/a"
    assert refang("203[.]0[.]113[.]45") == "203.0.113.45"
    assert defang("203.0.113.45", IOCType.IPV4) == "203[.]0[.]113[.]45"
    assert defang("https://evil.example.com/a", IOCType.URL) == "hxxps://evil[.]example[.]com/a"


def test_rfc1918_and_local_domains_marked_internal() -> None:
    lan_ip = classify_indicator("10.0.12.44")
    assert lan_ip is not None and lan_ip.is_internal is True
    corp_domain = classify_indicator("dc01.corp.local")
    assert corp_domain is not None and corp_domain.is_internal is True


def test_rfc5737_lab_ip_allowed_as_documentation() -> None:
    doc_ip = classify_indicator("203[.]0[.]113[.]45")
    assert doc_ip is not None and doc_ip.is_internal is False and doc_ip.is_documentation is True


def test_parse_mixed_text_deduplicates_and_filters_internal() -> None:
    report = parse_file(SAMPLES_DIR / "iocs_mixed.txt", include_internal=False)
    assert report.summary.unique_valid == 6
    assert report.summary.skipped_internal == 4
    assert report.summary.invalid_ignored == 1


def test_parse_detection_lab_alerts_json() -> None:
    report = parse_file(SAMPLES_DIR / "detection_lab_alerts.json", include_internal=False)
    values = {r.value for r in report.indicators}
    assert "203.0.113.45" in values
    assert "https://dropper.bad-actor.org/update.ps1" in values
    internal_values = {r.value for r in report.internal_indicators}
    assert "10.10.20.5" in internal_values
    assert "auth-gw.internal" in internal_values
