"""Bounded-queue async enrichment engine with WAL cache, scoring, Circuit Breaker, and Singleflight."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Sequence
from pathlib import Path

import httpx

from vtx_ti_enricher import __version__
from vtx_ti_enricher.cache import AsyncSQLiteCache
from vtx_ti_enricher.models import (
    BatchMetrics,
    EnrichBatchReport,
    EnrichedIOC,
    IOCRecord,
    ProviderMetrics,
    ProviderResult,
    ProviderStatus,
)
from vtx_ti_enricher.parser import parse_file
from vtx_ti_enricher.providers import ThreatIntelProvider, build_providers
from vtx_ti_enricher.resilience import (
    AsyncCircuitBreaker,
    AsyncSingleflight,
    AsyncTokenBucket,
)
from vtx_ti_enricher.scoring import ScoringPolicy, score_results

_Job = tuple[int, int, IOCRecord, ThreatIntelProvider]


class EnrichmentEngine:
    """Orchestrates bounded concurrent Threat Intel lookups with caching and deterministic scoring."""

    def __init__(
        self,
        providers: Sequence[ThreatIntelProvider] | None = None,
        cache: AsyncSQLiteCache | None = None,
        scoring_policy: ScoringPolicy | None = None,
        max_concurrency: int = 8,
        per_provider_concurrency: int = 4,
        queue_maxsize: int = 64,
        timeout_seconds: float = 10.0,
        rate_per_sec: float = 5.0,
        circuit_failure_threshold: int = 5,
        circuit_recovery_timeout: float = 30.0,
    ) -> None:
        self.providers: list[ThreatIntelProvider] = (
            list(providers) if providers is not None else list(build_providers())
        )
        self.cache = cache
        self.scoring_policy = scoring_policy
        self.max_concurrency = max(1, max_concurrency)
        self.per_provider_concurrency = max(1, min(per_provider_concurrency, self.max_concurrency))
        self.queue_maxsize = max(1, queue_maxsize)
        self.timeout_seconds = max(1.0, timeout_seconds)

        burst = max(1, int(rate_per_sec))
        self._buckets: dict[str, AsyncTokenBucket] = {
            p.name: AsyncTokenBucket(rate_per_sec=rate_per_sec, burst=burst)
            for p in self.providers
        }
        self._breakers: dict[str, AsyncCircuitBreaker] = {
            p.name: AsyncCircuitBreaker(
                failure_threshold=circuit_failure_threshold,
                recovery_timeout=circuit_recovery_timeout,
            )
            for p in self.providers
        }
        self.last_metrics: BatchMetrics = BatchMetrics(max_concurrency_limit=self.max_concurrency)

    def _build_client(self) -> httpx.AsyncClient:
        limits = httpx.Limits(
            max_connections=max(10, self.max_concurrency * 2),
            max_keepalive_connections=max(5, self.max_concurrency),
            keepalive_expiry=30.0,
        )
        timeout = httpx.Timeout(
            timeout=self.timeout_seconds,
            connect=min(5.0, self.timeout_seconds),
            read=self.timeout_seconds,
            write=min(5.0, self.timeout_seconds),
            pool=min(5.0, self.timeout_seconds),
        )
        return httpx.AsyncClient(
            timeout=timeout,
            limits=limits,
            headers={"User-Agent": f"vtx-ti-enricher/{__version__}"},
            follow_redirects=False,
        )

    def _aggregate_metrics(
        self,
        items: list[EnrichedIOC],
        duration_ms: float,
        peak_inflight: int,
        coalesced_hits: int,
        cache_hits_map: dict[str, int],
        cache_misses_map: dict[str, int],
    ) -> BatchMetrics:
        stats: dict[str, ProviderMetrics] = {
            p.name: ProviderMetrics(
                provider=p.name,
                cache_hits=cache_hits_map.get(p.name, 0),
                cache_misses=cache_misses_map.get(p.name, 0),
                circuit_state=self._breakers[p.name].state.value,
            )
            for p in self.providers
        }
        latencies: dict[str, list[float]] = {p.name: [] for p in self.providers}
        verdict_counts: dict[str, int] = {}

        for item in items:
            if item.assessment is not None:
                v_key = item.assessment.verdict.value
                verdict_counts[v_key] = verdict_counts.get(v_key, 0) + 1
            for res in item.provider_results:
                pm = stats[res.provider]
                if res.status == ProviderStatus.OK:
                    pm.requests_ok += 1
                elif res.status == ProviderStatus.NOT_FOUND:
                    pm.not_found += 1
                elif res.status in (
                    ProviderStatus.SKIPPED_UNSUPPORTED,
                    ProviderStatus.SKIPPED_NO_KEY,
                ):
                    pm.skipped += 1
                elif res.status == ProviderStatus.RATE_LIMITED:
                    pm.rate_limited += 1
                elif res.status == ProviderStatus.CIRCUIT_OPEN:
                    pm.circuit_short_circuited += 1
                else:
                    pm.errors += 1

                if res.attempts > 0:
                    latencies[res.provider].append(res.latency_ms)

        for name, vals in latencies.items():
            if vals:
                stats[name].avg_latency_ms = round(sum(vals) / len(vals), 2)

        return BatchMetrics(
            duration_ms=round(duration_ms, 2),
            max_concurrency_limit=self.max_concurrency,
            peak_inflight=peak_inflight,
            coalesced_hits=coalesced_hits,
            cache_hits=sum(cache_hits_map.values()),
            cache_misses=sum(cache_misses_map.values()),
            verdict_counts=verdict_counts,
            providers=stats,
        )

    async def enrich_batch(
        self,
        indicators: list[IOCRecord],
        client: httpx.AsyncClient | None = None,
    ) -> list[EnrichedIOC]:
        """Process a batch of IOCs using bounded queues, WAL cache, and deterministic scoring."""
        started = time.perf_counter()
        cache_hits_map = {p.name: 0 for p in self.providers}
        cache_misses_map = {p.name: 0 for p in self.providers}

        if not indicators or not self.providers:
            items = [
                EnrichedIOC(
                    ioc=ioc,
                    provider_results=[],
                    assessment=score_results([], policy=self.scoring_policy),
                )
                for ioc in indicators
            ]
            self.last_metrics = self._aggregate_metrics(
                items, 0.0, 0, 0, cache_hits_map, cache_misses_map
            )
            return items

        if self.cache is not None:
            await self.cache.initialize()

        total_jobs = len(indicators) * len(self.providers)
        results_grid: list[list[ProviderResult | None]] = [
            [None] * len(self.providers) for _ in indicators
        ]

        global_sem = asyncio.Semaphore(self.max_concurrency)
        provider_sems = {
            p.name: asyncio.Semaphore(self.per_provider_concurrency) for p in self.providers
        }
        singleflight: AsyncSingleflight[ProviderResult] = AsyncSingleflight()
        inflight_lock = asyncio.Lock()
        inflight = 0
        peak_inflight = 0

        async def _execute_provider_lookup(
            active_client: httpx.AsyncClient,
            provider: ThreatIntelProvider,
            ioc: IOCRecord,
        ) -> ProviderResult:
            nonlocal inflight, peak_inflight

            if not provider.supports(ioc.ioc_type) or not provider.is_configured():
                return await provider.query(active_client, ioc)

            sf_key = f"{provider.name}:{ioc.ioc_type.value}:{ioc.value}"

            async def _run_guarded() -> ProviderResult:
                nonlocal inflight, peak_inflight
                if self.cache is not None:
                    cached = await self.cache.get(provider.name, ioc.ioc_type, ioc.value)
                    if cached is not None:
                        cache_hits_map[provider.name] += 1
                        return cached
                    cache_misses_map[provider.name] += 1

                breaker = self._breakers[provider.name]
                if not await breaker.allow_request():
                    return ProviderResult(
                        provider=provider.name,
                        status=ProviderStatus.CIRCUIT_OPEN,
                        error=f"Circuit breaker OPEN for provider '{provider.name}'",
                        attempts=0,
                    )

                bucket = self._buckets[provider.name]
                await bucket.acquire()

                async with provider_sems[provider.name], global_sem:
                    async with inflight_lock:
                        inflight += 1
                        if inflight > peak_inflight:
                            peak_inflight = inflight
                    try:
                        res = await provider.query(
                            active_client,
                            ioc,
                            on_rate_limit=bucket.penalize,
                        )
                    finally:
                        async with inflight_lock:
                            inflight -= 1

                if res.status in (ProviderStatus.OK, ProviderStatus.NOT_FOUND):
                    await breaker.record_success()
                    if self.cache is not None:
                        await self.cache.set(ioc.ioc_type, ioc.value, res)
                elif res.status in (
                    ProviderStatus.ERROR,
                    ProviderStatus.TIMEOUT,
                    ProviderStatus.RATE_LIMITED,
                ):
                    await breaker.record_failure()
                return res

            result = await singleflight.do(sf_key, _run_guarded)
            return result.model_copy(deep=True)

        async def _run_pool(active_client: httpx.AsyncClient) -> None:
            queue: asyncio.Queue[_Job | None] = asyncio.Queue(maxsize=self.queue_maxsize)
            worker_count = min(self.max_concurrency, total_jobs)

            async def _worker() -> None:
                while True:
                    job = await queue.get()
                    try:
                        if job is None:
                            return
                        ioc_idx, prov_idx, ioc, provider = job
                        results_grid[ioc_idx][prov_idx] = await _execute_provider_lookup(
                            active_client,
                            provider,
                            ioc,
                        )
                    finally:
                        queue.task_done()

            workers = [asyncio.create_task(_worker()) for _ in range(worker_count)]
            try:
                for ioc_idx, ioc in enumerate(indicators):
                    for prov_idx, provider in enumerate(self.providers):
                        await queue.put((ioc_idx, prov_idx, ioc, provider))
                for _ in range(worker_count):
                    await queue.put(None)
                await queue.join()
                await asyncio.gather(*workers)
            finally:
                for task in workers:
                    if not task.done():
                        task.cancel()
                await asyncio.gather(*workers, return_exceptions=True)

        if client is not None:
            await _run_pool(client)
        else:
            async with self._build_client() as managed_client:
                await _run_pool(managed_client)

        items: list[EnrichedIOC] = []
        for idx, ioc in enumerate(indicators):
            prov_results = [r for r in results_grid[idx] if r is not None]
            assessment = score_results(prov_results, policy=self.scoring_policy)
            items.append(
                EnrichedIOC(
                    ioc=ioc,
                    provider_results=prov_results,
                    assessment=assessment,
                )
            )

        elapsed_ms = (time.perf_counter() - started) * 1000.0
        self.last_metrics = self._aggregate_metrics(
            items=items,
            duration_ms=elapsed_ms,
            peak_inflight=peak_inflight,
            coalesced_hits=singleflight.coalesced_hits,
            cache_hits_map=cache_hits_map,
            cache_misses_map=cache_misses_map,
        )
        return items

    async def enrich_file(
        self,
        path: Path,
        include_internal: bool = False,
        client: httpx.AsyncClient | None = None,
    ) -> EnrichBatchReport:
        """Parse an IOC file or vtx-detection-lab alert JSON and enrich all eligible indicators."""
        parsed = parse_file(path, include_internal=include_internal)
        items = await self.enrich_batch(parsed.indicators, client=client)
        return EnrichBatchReport(
            input_source=parsed.input_source,
            providers_enabled=[p.name for p in self.providers],
            total_enriched=len(items),
            skipped_internal=parsed.summary.skipped_internal,
            metrics=self.last_metrics,
            items=items,
        )
