"""Deterministic offline tests for Stage 3 WAL SQLite cache, verdict scoring, and CLI."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

import aiosqlite
import httpx
import pytest
import respx
from typer.testing import CliRunner

from vtx_ti_enricher.cache import AsyncSQLiteCache
from vtx_ti_enricher.engine import EnrichmentEngine
from vtx_ti_enricher.main import app
from vtx_ti_enricher.models import (
    ConfidenceLevel,
    IOCRecord,
    IOCType,
    ProviderResult,
    ProviderStatus,
    Verdict,
)
from vtx_ti_enricher.parser import classify_indicator
from vtx_ti_enricher.providers import AlienVaultOTXProvider, BaseProvider
from vtx_ti_enricher.scoring import score_results


def test_scoring_unknown_when_no_usable_telemetry() -> None:
    assessment = score_results(
        [
            ProviderResult(provider="abuseipdb", status=ProviderStatus.SKIPPED_NO_KEY),
            ProviderResult(provider="otx", status=ProviderStatus.TIMEOUT, error="timeout"),
        ]
    )
    assert assessment.verdict == Verdict.UNKNOWN
    assert assessment.confidence == ConfidenceLevel.NONE
    assert assessment.composite_score == 0.0
    assert assessment.responding_providers == 0
    assert len(assessment.reasons) == 1


def test_scoring_benign_high_confidence_with_clean_sources() -> None:
    assessment = score_results(
        [
            ProviderResult(provider="abuseipdb", status=ProviderStatus.OK, malicious_score=0),
            ProviderResult(provider="otx", status=ProviderStatus.OK, malicious_score=0),
        ]
    )
    assert assessment.verdict == Verdict.BENIGN
    assert assessment.confidence == ConfidenceLevel.HIGH
    assert assessment.composite_score == 0.0
    assert assessment.responding_providers == 2


def test_scoring_suspicious_floor_with_mixed_not_found() -> None:
    assessment = score_results(
        [
            ProviderResult(provider="otx", status=ProviderStatus.OK, malicious_score=45, detections=2),
            ProviderResult(provider="abuseipdb", status=ProviderStatus.NOT_FOUND),
        ]
    )
    assert assessment.verdict == Verdict.SUSPICIOUS
    assert assessment.confidence == ConfidenceLevel.MEDIUM
    assert assessment.composite_score == 30.0
    assert any("Suspicious signal floor" in r for r in assessment.reasons)


def test_scoring_malicious_strong_single_source_floor() -> None:
    assessment = score_results(
        [
            ProviderResult(
                provider="urlhaus",
                status=ProviderStatus.OK,
                malicious_score=95,
                detections=3,
                tags=["cobaltstrike", "malware_download"],
            ),
            ProviderResult(provider="otx", status=ProviderStatus.OK, malicious_score=0),
        ]
    )
    assert assessment.verdict == Verdict.MALICIOUS
    assert assessment.confidence == ConfidenceLevel.MEDIUM
    assert assessment.corroborated is False
    assert assessment.composite_score >= 70.0
    assert "cobaltstrike" in assessment.tags
    assert any("Strong single-source floor" in r for r in assessment.reasons)


def test_scoring_malicious_corroborated_high_confidence() -> None:
    assessment = score_results(
        [
            ProviderResult(
                provider="virustotal",
                status=ProviderStatus.OK,
                malicious_score=80,
                detections=6,
                total_engines=70,
                tags=["trojan"],
            ),
            ProviderResult(
                provider="urlhaus",
                status=ProviderStatus.OK,
                malicious_score=95,
                detections=2,
                tags=["powershell"],
            ),
        ]
    )
    assert assessment.verdict == Verdict.MALICIOUS
    assert assessment.confidence == ConfidenceLevel.HIGH
    assert assessment.corroborated is True
    assert assessment.malicious_providers == 2
    assert assessment.composite_score == 100.0
    assert assessment.tags == ["powershell", "trojan"]
    assert any("Multi-source corroboration" in r for r in assessment.reasons)


@pytest.mark.asyncio
async def test_sqlite_cache_wal_per_provider_ttl_and_negative_ttl(tmp_path: Path) -> None:
    now = [5000.0]
    db_file = tmp_path / "wal_cache.sqlite3"

    async with AsyncSQLiteCache(
        db_path=db_file,
        provider_ttls={"urlhaus": 300, "otx": 600},
        not_found_ttl_seconds=60,
        clock=lambda: now[0],
    ) as cache:
        ok_urlhaus = ProviderResult(provider="urlhaus", status=ProviderStatus.OK, malicious_score=90)
        nf_otx = ProviderResult(provider="otx", status=ProviderStatus.NOT_FOUND)
        err_res = ProviderResult(provider="otx", status=ProviderStatus.ERROR, error="503")

        assert await cache.set(IOCType.DOMAIN, "drop.example", ok_urlhaus) is True
        assert await cache.set(IOCType.IPV4, "203.0.113.10", nf_otx) is True
        assert await cache.set(IOCType.IPV4, "203.0.113.11", err_res) is False

        st = await cache.stats()
        assert st.journal_mode == "wal"
        assert st.total_entries == 2
        assert st.active_entries == 2
        assert st.by_provider == {"otx": 1, "urlhaus": 1}

        # Advance 61s: negative TTL (60s) expires, URLhaus (300s) stays active
        now[0] += 61.0
        assert await cache.get("otx", IOCType.IPV4, "203.0.113.10") is None
        hit = await cache.get("urlhaus", IOCType.DOMAIN, "drop.example")
        assert hit is not None
        assert hit.from_cache is True
        assert hit.attempts == 0
        assert hit.malicious_score == 90

        # Advance past 300s and purge expired entries
        now[0] += 300.0
        purged = await cache.purge_expired()
        assert purged == 1
        assert (await cache.stats()).total_entries == 0


@pytest.mark.asyncio
async def test_sqlite_cache_evicts_corrupted_json_gracefully(tmp_path: Path) -> None:
    now = [1000.0]
    db_file = tmp_path / "corrupt_cache.sqlite3"

    async with AsyncSQLiteCache(db_path=db_file, clock=lambda: now[0]) as cache:
        ok_res = ProviderResult(provider="otx", status=ProviderStatus.OK, malicious_score=25)
        await cache.set(IOCType.IPV4, "203.0.113.55", ok_res, ttl_seconds=600)

    async with aiosqlite.connect(str(db_file)) as raw_conn:
        await raw_conn.execute(
            "UPDATE ti_cache SET payload_json = ? WHERE ioc_value = ?",
            ("{invalid-json", "203.0.113.55"),
        )
        await raw_conn.commit()

    async with AsyncSQLiteCache(db_path=db_file, clock=lambda: now[0]) as cache:
        assert await cache.get("otx", IOCType.IPV4, "203.0.113.55") is None
        assert (await cache.stats()).total_entries == 0


@pytest.mark.asyncio
async def test_engine_wal_cache_hit_miss_expiry_and_scoring(tmp_path: Path) -> None:
    now = [10_000.0]
    db_file = tmp_path / "engine_cache.sqlite3"
    ip_ioc = classify_indicator("203.0.113.45")
    assert ip_ioc is not None

    with respx.mock(assert_all_called=False) as router:
        route = router.get("https://otx.alienvault.com/api/v1/indicators/IPv4/203.0.113.45/general")
        route.mock(
            return_value=httpx.Response(
                200,
                json={"pulse_info": {"count": 4, "pulses": [{"tags": ["c2"]}]}},
            )
        )

        async with AsyncSQLiteCache(
            db_path=db_file,
            provider_ttls={"otx": 120},
            clock=lambda: now[0],
        ) as cache:
            engine = EnrichmentEngine(
                providers=[AlienVaultOTXProvider(backoff_base=0.01)],
                cache=cache,
                rate_per_sec=100.0,
            )

            # 1st run: cache miss -> outbound HTTP
            first = await engine.enrich_batch([ip_ioc])
            assert route.call_count == 1
            assert engine.last_metrics.cache_misses == 1
            assert engine.last_metrics.cache_hits == 0
            assert first[0].provider_results[0].from_cache is False
            assert first[0].assessment is not None
            assert first[0].assessment.verdict == Verdict.MALICIOUS

            # 2nd run: cache hit -> zero outbound HTTP
            second = await engine.enrich_batch([ip_ioc])
            assert route.call_count == 1
            assert engine.last_metrics.cache_hits == 1
            assert engine.last_metrics.cache_misses == 0
            assert second[0].provider_results[0].from_cache is True
            assert second[0].provider_results[0].attempts == 0
            assert second[0].assessment is not None
            assert second[0].assessment.verdict == Verdict.MALICIOUS
            assert any("[cache]" in r for r in second[0].assessment.reasons)

            # 3rd run after TTL expiry -> re-fetches from upstream
            now[0] += 121.0
            third = await engine.enrich_batch([ip_ioc])
            assert route.call_count == 2
            assert engine.last_metrics.cache_misses == 1
            assert third[0].provider_results[0].from_cache is False


@pytest.mark.asyncio
async def test_engine_does_not_cache_transient_failures(tmp_path: Path) -> None:
    db_file = tmp_path / "transient_cache.sqlite3"
    ip_ioc = classify_indicator("203.0.113.77")
    assert ip_ioc is not None

    with respx.mock(assert_all_called=True) as router:
        route = router.get("https://otx.alienvault.com/api/v1/indicators/IPv4/203.0.113.77/general")
        route.side_effect = [
            httpx.Response(503, json={"error": "unavailable"}),
            httpx.Response(200, json={"pulse_info": {"count": 1, "pulses": []}}),
        ]

        async with AsyncSQLiteCache(db_path=db_file) as cache:
            engine = EnrichmentEngine(
                providers=[AlienVaultOTXProvider(max_retries=1, backoff_base=0.01)],
                cache=cache,
                rate_per_sec=100.0,
            )

            first = await engine.enrich_batch([ip_ioc])
            assert first[0].provider_results[0].status == ProviderStatus.ERROR
            assert await cache.get("otx", IOCType.IPV4, "203.0.113.77") is None

            second = await engine.enrich_batch([ip_ioc])
            assert second[0].provider_results[0].status == ProviderStatus.OK
            assert route.call_count == 2
            assert await cache.get("otx", IOCType.IPV4, "203.0.113.77") is not None


@pytest.mark.asyncio
async def test_engine_singleflight_prevents_cache_stampede(tmp_path: Path) -> None:
    call_count = 0

    class _SlowCountingProvider(BaseProvider):
        name = "slowcount"
        supported_types = {IOCType.IPV4}

        async def _lookup(self, client: httpx.AsyncClient, ioc: IOCRecord) -> ProviderResult:
            nonlocal call_count
            call_count += 1
            await asyncio.sleep(0.04)
            return ProviderResult(provider=self.name, status=ProviderStatus.OK, malicious_score=65)

    ip_ioc = classify_indicator("203.0.113.88")
    assert ip_ioc is not None

    async with AsyncSQLiteCache(db_path=tmp_path / "stampede.sqlite3") as cache:
        engine = EnrichmentEngine(
            providers=[_SlowCountingProvider()],
            cache=cache,
            max_concurrency=4,
            per_provider_concurrency=4,
            rate_per_sec=1000.0,
        )
        items = await engine.enrich_batch([ip_ioc, ip_ioc, ip_ioc])
        assert len(items) == 3
        assert call_count == 1
        assert engine.last_metrics.coalesced_hits == 2
        assert (await cache.stats()).active_entries == 1

        cached_run = await engine.enrich_batch([ip_ioc])
        assert call_count == 1
        assert engine.last_metrics.cache_hits == 1
        assert cached_run[0].provider_results[0].from_cache is True


def test_cli_cache_stats_purge_and_clear(tmp_path: Path) -> None:
    db_file = tmp_path / "cli_cache.sqlite3"

    async def _seed() -> None:
        async with AsyncSQLiteCache(db_path=db_file, clock=lambda: time.time() - 120.0) as old_cache:
            await old_cache.set(
                IOCType.IPV4,
                "203.0.113.1",
                ProviderResult(provider="otx", status=ProviderStatus.OK, malicious_score=10),
                ttl_seconds=10,
            )
        async with AsyncSQLiteCache(db_path=db_file) as fresh_cache:
            await fresh_cache.set(
                IOCType.DOMAIN,
                "evil.example",
                ProviderResult(provider="urlhaus", status=ProviderStatus.OK, malicious_score=90),
                ttl_seconds=3600,
            )

    asyncio.run(_seed())
    runner = CliRunner()

    res_stats = runner.invoke(app, ["cache-stats", "--cache-db", str(db_file)])
    assert res_stats.exit_code == 0
    assert "journal_mode=wal" in res_stats.output
    assert "total=2 | active=1 | expired=1" in res_stats.output

    res_purge = runner.invoke(app, ["cache-stats", "--cache-db", str(db_file), "--purge"])
    assert res_purge.exit_code == 0
    assert "Purged 1 expired cache entries." in res_purge.output
    assert "total=1 | active=1 | expired=0" in res_purge.output

    res_clear = runner.invoke(app, ["cache-stats", "--cache-db", str(db_file), "--clear"])
    assert res_clear.exit_code == 0
    assert "Cleared 1 cache entries." in res_clear.output
    assert "total=0 | active=0 | expired=0" in res_clear.output
