"""Strict Pydantic v2 data contracts for IOC parsing, caching, scoring, and async enrichment."""

from __future__ import annotations

from enum import Enum
from typing import Any
from pydantic import BaseModel, Field


class IOCType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"


class IOCRecord(BaseModel):
    ioc_type: IOCType
    value: str = Field(..., description="Canonical refanged indicator value.")
    defanged: str = Field(..., description="Safe-to-share defanged representation.")
    is_internal: bool = False
    is_documentation: bool = False
    sources: list[str] = Field(default_factory=list)


class ParseSummary(BaseModel):
    total_candidates: int = 0
    unique_valid: int = 0
    skipped_internal: int = 0
    invalid_ignored: int = 0
    by_type: dict[str, int] = Field(default_factory=dict)


class ParseReport(BaseModel):
    input_source: str
    summary: ParseSummary
    indicators: list[IOCRecord] = Field(default_factory=list)
    internal_indicators: list[IOCRecord] = Field(default_factory=list)


class ProviderStatus(str, Enum):
    OK = "ok"
    NOT_FOUND = "not_found"
    SKIPPED_UNSUPPORTED = "skipped_unsupported"
    SKIPPED_NO_KEY = "skipped_no_key"
    CIRCUIT_OPEN = "circuit_open"
    RATE_LIMITED = "rate_limited"
    TIMEOUT = "timeout"
    ERROR = "error"


class ProviderResult(BaseModel):
    provider: str
    status: ProviderStatus
    malicious_score: int | None = Field(default=None, ge=0, le=100)
    detections: int = Field(default=0, ge=0)
    total_engines: int = Field(default=0, ge=0)
    tags: list[str] = Field(default_factory=list)
    raw_summary: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    attempts: int = Field(default=1, ge=0)
    from_cache: bool = False
    latency_ms: float = Field(default=0.0, ge=0.0)


class Verdict(str, Enum):
    UNKNOWN = "unknown"
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class ConfidenceLevel(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class EvidenceContribution(BaseModel):
    provider: str
    status: ProviderStatus
    raw_score: int = Field(default=0, ge=0, le=100)
    effective_weight: float = Field(default=0.0, ge=0.0)
    weighted_points: float = Field(default=0.0, ge=0.0)
    detections: int = Field(default=0, ge=0)
    from_cache: bool = False


class VerdictAssessment(BaseModel):
    verdict: Verdict
    composite_score: float = Field(default=0.0, ge=0.0, le=100.0)
    confidence: ConfidenceLevel
    responding_providers: int = Field(default=0, ge=0)
    malicious_providers: int = Field(default=0, ge=0)
    corroborated: bool = False
    tags: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    recommended_action: str
    evidence: list[EvidenceContribution] = Field(default_factory=list)


class EnrichedIOC(BaseModel):
    ioc: IOCRecord
    provider_results: list[ProviderResult] = Field(default_factory=list)
    assessment: VerdictAssessment | None = None


class ProviderMetrics(BaseModel):
    provider: str
    requests_ok: int = 0
    not_found: int = 0
    skipped: int = 0
    rate_limited: int = 0
    circuit_short_circuited: int = 0
    errors: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    avg_latency_ms: float = 0.0
    circuit_state: str = "closed"


class BatchMetrics(BaseModel):
    duration_ms: float = 0.0
    max_concurrency_limit: int = 0
    peak_inflight: int = 0
    coalesced_hits: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    verdict_counts: dict[str, int] = Field(default_factory=dict)
    providers: dict[str, ProviderMetrics] = Field(default_factory=dict)


class CacheStats(BaseModel):
    db_path: str
    journal_mode: str
    total_entries: int = 0
    active_entries: int = 0
    expired_entries: int = 0
    by_provider: dict[str, int] = Field(default_factory=dict)


class EnrichBatchReport(BaseModel):
    schema_version: str = "3.0"
    input_source: str
    providers_enabled: list[str]
    total_enriched: int
    skipped_internal: int
    metrics: BatchMetrics = Field(default_factory=BatchMetrics)
    items: list[EnrichedIOC] = Field(default_factory=list)
