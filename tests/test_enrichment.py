"""Deterministic offline tests for Stage 2 async architecture, resilience, and OPSEC."""

from __future__ import annotations

import asyncio
import base64
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from pathlib import Path

import httpx
import pytest
import respx

from vtx_ti_enricher.engine import EnrichmentEngine
from vtx_ti_enricher.models import IOCRecord, IOCType, ProviderResult, ProviderStatus
from vtx_ti_enricher.parser import classify_indicator
from vtx_ti_enricher.providers import (
    AbuseIPDBProvider,
    AlienVaultOTXProvider,
    BaseProvider,
    URLhausProvider,
    VirusTotalProvider,
    parse_retry_after,
)

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"


def test_parse_retry_after_delta_rfc7231_and_invalid() -> None:
    now = datetime.now(timezone.utc)
    future_hdr = format_datetime(now + timedelta(seconds=20), usegmt=True)
    past_hdr = format_datetime(now - timedelta(seconds=20), usegmt=True)

    assert parse_retry_after("12") == 12.0
    assert parse_retry_after("180", max_seconds=60.0) == 60.0
    assert parse_retry_after("0") is None
    assert parse_retry_after("-3") is None
    parsed_future = parse_retry_after(future_hdr)
    assert parsed_future is not None and 15.0 <= parsed_future <= 21.0
    assert parse_retry_after(past_hdr) is None
    assert parse_retry_after("invalid-value") is None
    assert parse_retry_after(None) is None


@pytest.mark.asyncio
async def test_all_four_providers_success_offline() -> None:
    ip_ioc = classify_indicator("203.0.113.45")
    url_ioc = classify_indicator("https://dropper.bad-actor.org/update.ps1")
    assert ip_ioc is not None and url_ioc is not None

    url_vt_id = base64.urlsafe_b64encode(url_ioc.value.encode()).decode().rstrip("=")

    with respx.mock(assert_all_called=False) as router:
        router.get("https://api.abuseipdb.com/api/v2/check").mock(
            return_value=httpx.Response(
                200,
                json={
                    "data": {
                        "abuseConfidenceScore": 92,
                        "totalReports": 41,
                        "countryCode": "NL",
                        "isp": "Bulletproof Hosting",
                        "isTor": True,
                    }
                },
            )
        )
        router.get("https://otx.alienvault.com/api/v1/indicators/IPv4/203.0.113.45/general").mock(
            return_value=httpx.Response(
                200,
                json={
                    "reputation": -3,
                    "pulse_info": {
                        "count": 4,
                        "pulses": [{"tags": ["ssh-bruteforce", "Botnet"]}],
                    },
                },
            )
        )
        router.post("https://urlhaus-api.abuse.ch/v1/url/").mock(
            return_value=httpx.Response(
                200,
                json={
                    "query_status": "ok",
                    "url_status": "online",
                    "threat": "malware_download",
                    "tags": ["powershell", "cobaltstrike"],
                },
            )
        )
        router.get("https://www.virustotal.com/api/v3/ip_addresses/203.0.113.45").mock(
            return_value=httpx.Response(
                200,
                json={
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {
                                "malicious": 8,
                                "suspicious": 1,
                                "harmless": 60,
                                "undetected": 15,
                            },
                            "tags": ["scanner"],
                        }
                    }
                },
            )
        )
        router.get(f"https://www.virustotal.com/api/v3/urls/{url_vt_id}").mock(
            return_value=httpx.Response(
                200,
                json={
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {
                                "malicious": 6,
                                "suspicious": 0,
                                "harmless": 70,
                                "undetected": 10,
                            }
                        }
                    }
                },
            )
        )

        providers = [
            AbuseIPDBProvider(api_key="unit-test-abuse", backoff_base=0.01),
            AlienVaultOTXProvider(backoff_base=0.01),
            URLhausProvider(backoff_base=0.01),
            VirusTotalProvider(api_key="unit-test-vt", backoff_base=0.01),
        ]
        engine = EnrichmentEngine(providers=providers, max_concurrency=4, rate_per_sec=100.0)
        results = await engine.enrich_batch([ip_ioc, url_ioc])

    by_val = {item.ioc.value: {r.provider: r for r in item.provider_results} for item in results}

    assert by_val["203.0.113.45"]["abuseipdb"].status == ProviderStatus.OK
    assert by_val["203.0.113.45"]["abuseipdb"].malicious_score == 92
    assert "tor-exit" in by_val["203.0.113.45"]["abuseipdb"].tags
    assert by_val["203.0.113.45"]["otx"].detections == 4
    assert by_val["203.0.113.45"]["urlhaus"].status == ProviderStatus.SKIPPED_UNSUPPORTED
    assert by_val["203.0.113.45"]["virustotal"].detections == 8

    assert by_val[url_ioc.value]["abuseipdb"].status == ProviderStatus.SKIPPED_UNSUPPORTED
    assert by_val[url_ioc.value]["urlhaus"].malicious_score == 95
    assert by_val[url_ioc.value]["virustotal"].detections == 6


@pytest.mark.asyncio
async def test_missing_api_key_skips_with_zero_outbound_http(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("VT_API_KEY", raising=False)

    ip_ioc = classify_indicator("198.51.100.77")
    assert ip_ioc is not None

    with respx.mock(assert_all_called=False) as router:
        engine = EnrichmentEngine(
            providers=[AbuseIPDBProvider(), VirusTotalProvider()],
            rate_per_sec=100.0,
        )
        items = await engine.enrich_batch([ip_ioc])
        assert len(router.calls) == 0

    statuses = {r.provider: (r.status, r.attempts) for r in items[0].provider_results}
    assert statuses == {
        "abuseipdb": (ProviderStatus.SKIPPED_NO_KEY, 0),
        "virustotal": (ProviderStatus.SKIPPED_NO_KEY, 0),
    }


@pytest.mark.asyncio
async def test_retry_after_on_429_then_recovers() -> None:
    ip_ioc = classify_indicator("203.0.113.45")
    assert ip_ioc is not None

    with respx.mock(assert_all_called=True) as router:
        route = router.get("https://otx.alienvault.com/api/v1/indicators/IPv4/203.0.113.45/general")
        route.side_effect = [
            httpx.Response(429, headers={"Retry-After": "0.02"}, json={"detail": "rate limit"}),
            httpx.Response(200, json={"pulse_info": {"count": 3, "pulses": []}}),
        ]

        provider = AlienVaultOTXProvider(max_retries=3, backoff_base=0.01)
        engine = EnrichmentEngine(providers=[provider], rate_per_sec=100.0)
        items = await engine.enrich_batch([ip_ioc])

    res = items[0].provider_results[0]
    assert route.call_count == 2
    assert res.status == ProviderStatus.OK
    assert res.attempts == 2
    assert res.detections == 3


@pytest.mark.asyncio
async def test_anti_ssrf_blocks_http_redirects() -> None:
    ip_ioc = classify_indicator("203.0.113.45")
    assert ip_ioc is not None

    with respx.mock(assert_all_called=False) as router:
        router.get("https://otx.alienvault.com/api/v1/indicators/IPv4/203.0.113.45/general").mock(
            return_value=httpx.Response(
                302,
                headers={"Location": "http://169.254.169.254/latest/meta-data/"},
            )
        )

        engine = EnrichmentEngine(
            providers=[AlienVaultOTXProvider(max_retries=1, backoff_base=0.01)],
            rate_per_sec=100.0,
        )
        items = await engine.enrich_batch([ip_ioc])
        assert len(router.calls) == 1

    res = items[0].provider_results[0]
    assert res.status == ProviderStatus.ERROR
    assert res.error is not None and "redirect" in res.error.lower()


@pytest.mark.asyncio
async def test_circuit_breaker_opens_short_circuits_and_recovers() -> None:
    iocs = [classify_indicator(f"203.0.113.{i}") for i in range(1, 6)]
    valid = [x for x in iocs if x is not None]

    with respx.mock(assert_all_called=False) as router:
        route = router.get(url__startswith="https://otx.alienvault.com/api/v1/indicators/IPv4/")
        route.mock(return_value=httpx.Response(503, json={"error": "upstream down"}))

        engine = EnrichmentEngine(
            providers=[AlienVaultOTXProvider(max_retries=1, backoff_base=0.01)],
            max_concurrency=1,
            per_provider_concurrency=1,
            rate_per_sec=100.0,
            circuit_failure_threshold=2,
            circuit_recovery_timeout=0.08,
        )

        first_batch = await engine.enrich_batch(valid[:4])
        statuses = [item.provider_results[0].status for item in first_batch]
        assert statuses == [
            ProviderStatus.ERROR,
            ProviderStatus.ERROR,
            ProviderStatus.CIRCUIT_OPEN,
            ProviderStatus.CIRCUIT_OPEN,
        ]
        assert route.call_count == 2
        assert engine.last_metrics.providers["otx"].circuit_short_circuited == 2
        assert engine.last_metrics.providers["otx"].circuit_state == "open"

        # Wait past recovery_timeout so breaker probes in HALF_OPEN and closes on success
        await asyncio.sleep(0.1)
        route.mock(return_value=httpx.Response(200, json={"pulse_info": {"count": 1, "pulses": []}}))

        recovered = await engine.enrich_batch([valid[4]])
        assert recovered[0].provider_results[0].status == ProviderStatus.OK
        assert route.call_count == 3
        assert engine.last_metrics.providers["otx"].circuit_state == "closed"


@pytest.mark.asyncio
async def test_singleflight_coalesces_concurrent_identical_lookups() -> None:
    call_count = 0

    class _CountingSlowProvider(BaseProvider):
        name = "counting"
        supported_types = {IOCType.IPV4}

        async def _lookup(self, client: httpx.AsyncClient, ioc: IOCRecord) -> ProviderResult:
            nonlocal call_count
            call_count += 1
            await asyncio.sleep(0.05)
            return ProviderResult(provider=self.name, status=ProviderStatus.OK, malicious_score=42)

    ioc = classify_indicator("203.0.113.99")
    assert ioc is not None

    engine = EnrichmentEngine(
        providers=[_CountingSlowProvider()],
        max_concurrency=4,
        per_provider_concurrency=4,
        rate_per_sec=1000.0,
    )
    items = await engine.enrich_batch([ioc, ioc, ioc])

    assert len(items) == 3
    assert call_count == 1
    assert engine.last_metrics.coalesced_hits == 2
    assert all(item.provider_results[0].malicious_score == 42 for item in items)


@pytest.mark.asyncio
async def test_bounded_concurrency_respects_global_limit() -> None:
    class _SlowProvider(BaseProvider):
        name = "slow"
        supported_types = {IOCType.IPV4}

        async def _lookup(self, client: httpx.AsyncClient, ioc: IOCRecord) -> ProviderResult:
            await asyncio.sleep(0.03)
            return ProviderResult(provider=self.name, status=ProviderStatus.OK, malicious_score=5)

    iocs = [classify_indicator(f"203.0.113.{i}") for i in range(1, 10)]
    valid = [x for x in iocs if x is not None]

    engine = EnrichmentEngine(
        providers=[_SlowProvider()],
        max_concurrency=3,
        per_provider_concurrency=3,
        queue_maxsize=4,
        rate_per_sec=1000.0,
    )
    items = await engine.enrich_batch(valid)

    assert len(items) == 9
    assert 1 <= engine.last_metrics.peak_inflight <= 3


@pytest.mark.asyncio
async def test_timeout_degrades_gracefully_without_impacting_healthy_provider() -> None:
    ip_ioc = classify_indicator("203.0.113.45")
    assert ip_ioc is not None

    with respx.mock(assert_all_called=False) as router:
        router.get("https://api.abuseipdb.com/api/v2/check").mock(
            side_effect=httpx.ReadTimeout("upstream read timeout")
        )
        router.get("https://otx.alienvault.com/api/v1/indicators/IPv4/203.0.113.45/general").mock(
            return_value=httpx.Response(200, json={"pulse_info": {"count": 2, "pulses": []}})
        )

        providers = [
            AbuseIPDBProvider(api_key="unit-test-token", max_retries=2, backoff_base=0.01),
            AlienVaultOTXProvider(max_retries=2, backoff_base=0.01),
        ]
        engine = EnrichmentEngine(providers=providers, rate_per_sec=100.0)
        items = await engine.enrich_batch([ip_ioc])

    by_provider = {r.provider: r for r in items[0].provider_results}
    assert by_provider["abuseipdb"].status == ProviderStatus.TIMEOUT
    assert by_provider["abuseipdb"].attempts == 2
    assert by_provider["otx"].status == ProviderStatus.OK
    assert by_provider["otx"].detections == 2


@pytest.mark.asyncio
async def test_detection_lab_alerts_never_leak_internal_assets() -> None:
    with respx.mock(assert_all_called=False) as router:
        router.get(url__startswith="https://otx.alienvault.com/api/v1/indicators/").mock(
            return_value=httpx.Response(200, json={"pulse_info": {"count": 0, "pulses": []}})
        )
        router.post(url__startswith="https://urlhaus-api.abuse.ch/v1/").mock(
            return_value=httpx.Response(200, json={"query_status": "no_results"})
        )

        engine = EnrichmentEngine(
            providers=[AlienVaultOTXProvider(backoff_base=0.01), URLhausProvider(backoff_base=0.01)],
            max_concurrency=4,
            rate_per_sec=100.0,
        )
        report = await engine.enrich_file(SAMPLES_DIR / "detection_lab_alerts.json")

        for call in router.calls:
            req_url = str(call.request.url)
            req_body = call.request.content.decode("utf-8", errors="ignore")
            assert "10.10.20.5" not in req_url and "10.10.20.5" not in req_body
            assert "auth-gw.internal" not in req_url and "auth-gw.internal" not in req_body

    assert report.total_enriched == 4
    assert report.skipped_internal == 2
    assert report.metrics.duration_ms > 0
