"""Hardened async Threat Intelligence providers with Protocol, Retry-After, and anti-SSRF hygiene."""

from __future__ import annotations

import asyncio
import base64
import os
import time
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Protocol, runtime_checkable
from urllib.parse import quote

import httpx

from vtx_ti_enricher.models import IOCRecord, IOCType, ProviderResult, ProviderStatus
from vtx_ti_enricher.resilience import compute_backoff_seconds

RateLimitHook = Callable[[float], Awaitable[None]]


class _TransientProviderError(Exception):
    """Retryable upstream failure carrying status classification and optional Retry-After."""

    def __init__(
        self,
        message: str,
        status: ProviderStatus,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after


def parse_retry_after(header_value: str | None, max_seconds: float = 60.0) -> float | None:
    """Parse HTTP Retry-After header (delta-seconds or HTTP-date) into clamped seconds."""
    if not header_value:
        return None
    raw = header_value.strip()
    if not raw:
        return None
    try:
        seconds = float(raw)
        return max(0.0, min(seconds, max_seconds)) if seconds > 0 else None
    except ValueError:
        pass
    try:
        target = parsedate_to_datetime(raw)
        if target.tzinfo is None:
            target = target.replace(tzinfo=timezone.utc)
        delta = (target - datetime.now(timezone.utc)).total_seconds()
        return max(0.0, min(delta, max_seconds)) if delta > 0 else None
    except (TypeError, ValueError, OverflowError):
        return None


@runtime_checkable
class ThreatIntelProvider(Protocol):
    """Structural contract satisfied by built-in and custom async Threat Intel providers."""

    name: str
    supported_types: set[IOCType]
    requires_api_key: bool
    api_key: str | None

    def supports(self, ioc_type: IOCType) -> bool: ...

    def is_configured(self) -> bool: ...

    async def query(
        self,
        client: httpx.AsyncClient,
        ioc: IOCRecord,
        on_rate_limit: RateLimitHook | None = None,
    ) -> ProviderResult: ...


class BaseProvider(ABC):
    """Resilient template-method base class for async Threat Intelligence connectors."""

    name: str
    supported_types: set[IOCType]
    requires_api_key: bool = False
    api_key_env: str | None = None

    def __init__(
        self,
        api_key: str | None = None,
        max_retries: int = 3,
        backoff_base: float = 0.2,
        max_backoff: float = 4.0,
    ) -> None:
        env_key = os.getenv(self.api_key_env) if self.api_key_env else None
        self.api_key = api_key if api_key is not None else env_key
        self.max_retries = max(1, max_retries)
        self.backoff_base = max(0.01, backoff_base)
        self.max_backoff = max(self.backoff_base, max_backoff)

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type in self.supported_types

    def is_configured(self) -> bool:
        return (not self.requires_api_key) or bool(self.api_key)

    async def query(
        self,
        client: httpx.AsyncClient,
        ioc: IOCRecord,
        on_rate_limit: RateLimitHook | None = None,
    ) -> ProviderResult:
        """Execute lookup with bounded jittered retries, Retry-After feedback, and isolation."""
        if not self.supports(ioc.ioc_type):
            return ProviderResult(
                provider=self.name,
                status=ProviderStatus.SKIPPED_UNSUPPORTED,
                attempts=0,
            )

        if not self.is_configured():
            return ProviderResult(
                provider=self.name,
                status=ProviderStatus.SKIPPED_NO_KEY,
                error=f"Missing environment variable {self.api_key_env}",
                attempts=0,
            )

        start = time.perf_counter()
        last_error: _TransientProviderError | None = None

        for attempt in range(1, self.max_retries + 1):
            try:
                result = await self._lookup(client, ioc)
                result.attempts = attempt
                result.latency_ms = round((time.perf_counter() - start) * 1000.0, 2)
                return result
            except _TransientProviderError as exc:
                last_error = exc
                delay = compute_backoff_seconds(
                    attempt=attempt,
                    base_delay=self.backoff_base,
                    max_delay=self.max_backoff,
                    retry_after=exc.retry_after,
                )
                if exc.status == ProviderStatus.RATE_LIMITED and on_rate_limit is not None:
                    await on_rate_limit(delay)
                if attempt < self.max_retries:
                    await asyncio.sleep(delay)
            except Exception as exc:  # noqa: BLE001 - isolate provider faults from the batch
                return ProviderResult(
                    provider=self.name,
                    status=ProviderStatus.ERROR,
                    error=str(exc),
                    attempts=attempt,
                    latency_ms=round((time.perf_counter() - start) * 1000.0, 2),
                )

        elapsed = round((time.perf_counter() - start) * 1000.0, 2)
        return ProviderResult(
            provider=self.name,
            status=last_error.status if last_error else ProviderStatus.ERROR,
            error=str(last_error) if last_error else "Retries exhausted",
            attempts=self.max_retries,
            latency_ms=elapsed,
        )

    async def _request(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> httpx.Response:
        """Perform an outbound HTTP call with anti-SSRF redirect blocking and transient classification."""
        kwargs["follow_redirects"] = False
        try:
            resp = await client.request(method, url, **kwargs)
        except httpx.TimeoutException as exc:
            raise _TransientProviderError(
                f"Upstream timeout: {exc}",
                status=ProviderStatus.TIMEOUT,
            ) from exc
        except httpx.TransportError as exc:
            raise _TransientProviderError(
                f"Transport error: {exc}",
                status=ProviderStatus.ERROR,
            ) from exc

        if resp.status_code == 429:
            retry_after = parse_retry_after(resp.headers.get("Retry-After"))
            raise _TransientProviderError(
                "HTTP 429 rate limited",
                status=ProviderStatus.RATE_LIMITED,
                retry_after=retry_after,
            )
        if resp.status_code >= 500:
            retry_after = parse_retry_after(resp.headers.get("Retry-After"))
            raise _TransientProviderError(
                f"HTTP {resp.status_code} upstream server error",
                status=ProviderStatus.ERROR,
                retry_after=retry_after,
            )
        return resp

    def _handle_non_2xx(self, resp: httpx.Response) -> ProviderResult | None:
        if 200 <= resp.status_code < 300:
            return None
        if resp.status_code == 404:
            return ProviderResult(provider=self.name, status=ProviderStatus.NOT_FOUND)
        if 300 <= resp.status_code < 400:
            return ProviderResult(
                provider=self.name,
                status=ProviderStatus.ERROR,
                error=f"Blocked unexpected HTTP {resp.status_code} redirect",
            )
        return ProviderResult(
            provider=self.name,
            status=ProviderStatus.ERROR,
            error=f"HTTP {resp.status_code}",
        )

    @staticmethod
    def _safe_json_dict(resp: httpx.Response) -> dict[str, Any]:
        payload = resp.json()
        if not isinstance(payload, dict):
            raise ValueError("Unexpected non-object JSON payload from upstream")
        return payload

    @abstractmethod
    async def _lookup(self, client: httpx.AsyncClient, ioc: IOCRecord) -> ProviderResult:
        """Provider-specific request execution and response normalization."""


class AbuseIPDBProvider(BaseProvider):
    """AbuseIPDB v2 IP reputation connector."""

    name = "abuseipdb"
    supported_types = {IOCType.IPV4, IOCType.IPV6}
    requires_api_key = True
    api_key_env = "ABUSEIPDB_API_KEY"
    base_url = "https://api.abuseipdb.com/api/v2/check"

    async def _lookup(self, client: httpx.AsyncClient, ioc: IOCRecord) -> ProviderResult:
        resp = await self._request(
            client,
            "GET",
            self.base_url,
            headers={"Key": self.api_key or "", "Accept": "application/json"},
            params={"ipAddress": ioc.value, "maxAgeInDays": "90"},
        )
        non_2xx = self._handle_non_2xx(resp)
        if non_2xx is not None:
            return non_2xx

        body = self._safe_json_dict(resp)
        payload = body.get("data") if isinstance(body.get("data"), dict) else {}
        confidence = int(payload.get("abuseConfidenceScore") or 0)
        reports = int(payload.get("totalReports") or 0)

        tags: list[str] = []
        if payload.get("usageType"):
            tags.append(str(payload["usageType"]).strip().lower())
        if payload.get("isTor"):
            tags.append("tor-exit")

        return ProviderResult(
            provider=self.name,
            status=ProviderStatus.OK,
            malicious_score=max(0, min(100, confidence)),
            detections=max(0, reports),
            tags=tags,
            raw_summary={
                "country_code": payload.get("countryCode"),
                "isp": payload.get("isp"),
                "total_reports": reports,
                "abuse_confidence_score": confidence,
            },
        )


class AlienVaultOTXProvider(BaseProvider):
    """AlienVault OTX v1 general indicator connector."""

    name = "otx"
    supported_types = {
        IOCType.IPV4,
        IOCType.IPV6,
        IOCType.DOMAIN,
        IOCType.MD5,
        IOCType.SHA1,
        IOCType.SHA256,
    }
    requires_api_key = False
    api_key_env = "OTX_API_KEY"
    base_url = "https://otx.alienvault.com/api/v1/indicators"

    _SECTION_MAP = {
        IOCType.IPV4: "IPv4",
        IOCType.IPV6: "IPv6",
        IOCType.DOMAIN: "domain",
        IOCType.MD5: "file",
        IOCType.SHA1: "file",
        IOCType.SHA256: "file",
    }

    async def _lookup(self, client: httpx.AsyncClient, ioc: IOCRecord) -> ProviderResult:
        section = self._SECTION_MAP[ioc.ioc_type]
        safe_val = quote(ioc.value, safe="")
        url = f"{self.base_url}/{section}/{safe_val}/general"
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["X-OTX-API-KEY"] = self.api_key

        resp = await self._request(client, "GET", url, headers=headers)
        non_2xx = self._handle_non_2xx(resp)
        if non_2xx is not None:
            return non_2xx

        data = self._safe_json_dict(resp)
        pulse_info = data.get("pulse_info") if isinstance(data.get("pulse_info"), dict) else {}
        pulse_count = max(0, int(pulse_info.get("count") or 0))
        tags_set: set[str] = set()
        pulses = pulse_info.get("pulses") if isinstance(pulse_info.get("pulses"), list) else []
        for pulse in pulses[:10]:
            if not isinstance(pulse, dict):
                continue
            for tag in pulse.get("tags") or []:
                if isinstance(tag, str) and tag.strip():
                    tags_set.add(tag.strip().lower())

        score = 0 if pulse_count == 0 else min(100, 25 + pulse_count * 15)
        return ProviderResult(
            provider=self.name,
            status=ProviderStatus.OK,
            malicious_score=score,
            detections=pulse_count,
            tags=sorted(tags_set)[:10],
            raw_summary={
                "pulse_count": pulse_count,
                "reputation": data.get("reputation"),
            },
        )


class URLhausProvider(BaseProvider):
    """abuse.ch URLhaus v1 malware URL / host / payload connector."""

    name = "urlhaus"
    supported_types = {IOCType.URL, IOCType.DOMAIN, IOCType.MD5, IOCType.SHA256}
    requires_api_key = False
    api_key_env = "URLHAUS_AUTH_KEY"
    base_url = "https://urlhaus-api.abuse.ch/v1"

    async def _lookup(self, client: httpx.AsyncClient, ioc: IOCRecord) -> ProviderResult:
        if ioc.ioc_type == IOCType.URL:
            endpoint, form_data = f"{self.base_url}/url/", {"url": ioc.value}
        elif ioc.ioc_type == IOCType.DOMAIN:
            endpoint, form_data = f"{self.base_url}/host/", {"host": ioc.value}
        elif ioc.ioc_type == IOCType.MD5:
            endpoint, form_data = f"{self.base_url}/payload/", {"md5_hash": ioc.value}
        else:
            endpoint, form_data = f"{self.base_url}/payload/", {"sha256_hash": ioc.value}

        headers = {"Auth-Key": self.api_key} if self.api_key else {}
        resp = await self._request(client, "POST", endpoint, data=form_data, headers=headers)
        non_2xx = self._handle_non_2xx(resp)
        if non_2xx is not None:
            return non_2xx

        data = self._safe_json_dict(resp)
        query_status = str(data.get("query_status") or "")
        if query_status in {"no_results", "invalid_url", "invalid_host"}:
            return ProviderResult(provider=self.name, status=ProviderStatus.NOT_FOUND)
        if query_status != "ok":
            return ProviderResult(
                provider=self.name,
                status=ProviderStatus.ERROR,
                error=f"URLhaus status: {query_status}",
            )

        tags = [t.strip().lower() for t in (data.get("tags") or []) if isinstance(t, str) and t.strip()]
        if data.get("signature"):
            tags.append(str(data["signature"]).strip().lower())
        if data.get("threat"):
            tags.append(str(data["threat"]).strip().lower())

        url_status = str(data.get("url_status") or "").lower()
        urls_count = max(0, int(data.get("url_count") or (1 if data.get("url") else 0)))
        score = 95 if url_status == "online" else 80

        return ProviderResult(
            provider=self.name,
            status=ProviderStatus.OK,
            malicious_score=score,
            detections=max(1, urls_count),
            tags=sorted(set(tags))[:10],
            raw_summary={
                "threat": data.get("threat"),
                "url_status": data.get("url_status"),
                "signature": data.get("signature"),
                "url_count": urls_count,
            },
        )


class VirusTotalProvider(BaseProvider):
    """VirusTotal v3 multi-IOC reputation connector."""

    name = "virustotal"
    supported_types = {
        IOCType.IPV4,
        IOCType.IPV6,
        IOCType.DOMAIN,
        IOCType.URL,
        IOCType.MD5,
        IOCType.SHA1,
        IOCType.SHA256,
    }
    requires_api_key = True
    api_key_env = "VT_API_KEY"
    base_url = "https://www.virustotal.com/api/v3"

    async def _lookup(self, client: httpx.AsyncClient, ioc: IOCRecord) -> ProviderResult:
        if ioc.ioc_type in (IOCType.IPV4, IOCType.IPV6):
            endpoint = f"{self.base_url}/ip_addresses/{quote(ioc.value, safe='')}"
        elif ioc.ioc_type == IOCType.DOMAIN:
            endpoint = f"{self.base_url}/domains/{quote(ioc.value, safe='')}"
        elif ioc.ioc_type == IOCType.URL:
            url_id = base64.urlsafe_b64encode(ioc.value.encode("utf-8")).decode("ascii").rstrip("=")
            endpoint = f"{self.base_url}/urls/{url_id}"
        else:
            endpoint = f"{self.base_url}/files/{quote(ioc.value, safe='')}"

        resp = await self._request(
            client,
            "GET",
            endpoint,
            headers={"x-apikey": self.api_key or "", "Accept": "application/json"},
        )
        non_2xx = self._handle_non_2xx(resp)
        if non_2xx is not None:
            return non_2xx

        body = self._safe_json_dict(resp)
        data_node = body.get("data") if isinstance(body.get("data"), dict) else {}
        attrs = data_node.get("attributes") if isinstance(data_node.get("attributes"), dict) else {}
        stats = attrs.get("last_analysis_stats") if isinstance(attrs.get("last_analysis_stats"), dict) else {}

        malicious = max(0, int(stats.get("malicious") or 0))
        suspicious = max(0, int(stats.get("suspicious") or 0))
        total = sum(max(0, int(v or 0)) for v in stats.values()) if stats else 0
        score = 0 if (malicious == 0 and suspicious == 0) else min(100, malicious * 15 + suspicious * 5)
        tags = [t.strip().lower() for t in (attrs.get("tags") or []) if isinstance(t, str) and t.strip()][:10]

        return ProviderResult(
            provider=self.name,
            status=ProviderStatus.OK,
            malicious_score=score,
            detections=malicious,
            total_engines=total,
            tags=tags,
            raw_summary={
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": int(stats.get("harmless") or 0),
                "undetected": int(stats.get("undetected") or 0),
                "reputation": attrs.get("reputation"),
            },
        )


PROVIDER_REGISTRY: dict[str, type[BaseProvider]] = {
    AbuseIPDBProvider.name: AbuseIPDBProvider,
    AlienVaultOTXProvider.name: AlienVaultOTXProvider,
    URLhausProvider.name: URLhausProvider,
    VirusTotalProvider.name: VirusTotalProvider,
}


def build_providers(
    names: list[str] | None = None,
    max_retries: int = 3,
    backoff_base: float = 0.2,
    max_backoff: float = 4.0,
) -> list[BaseProvider]:
    """Instantiate configured providers by name."""
    selected = names if names else list(PROVIDER_REGISTRY.keys())
    providers: list[BaseProvider] = []
    for raw_name in selected:
        key = raw_name.strip().lower()
        if key not in PROVIDER_REGISTRY:
            valid = ", ".join(sorted(PROVIDER_REGISTRY.keys()))
            raise ValueError(f"Unknown provider '{raw_name}'. Valid providers: {valid}")
        providers.append(
            PROVIDER_REGISTRY[key](
                max_retries=max_retries,
                backoff_base=backoff_base,
                max_backoff=max_backoff,
            )
        )
    return providers
