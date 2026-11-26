"""Deterministic Threat Intelligence verdict engine with explainability and SOC actions."""

from __future__ import annotations

from pydantic import BaseModel, Field

from vtx_ti_enricher.models import (
    ConfidenceLevel,
    EvidenceContribution,
    ProviderResult,
    ProviderStatus,
    Verdict,
    VerdictAssessment,
)

DEFAULT_PROVIDER_WEIGHTS: dict[str, float] = {
    "virustotal": 0.35,
    "urlhaus": 0.30,
    "abuseipdb": 0.20,
    "otx": 0.15,
}


class ScoringPolicy(BaseModel):
    """Configurable deterministic thresholds and provider weights."""

    provider_weights: dict[str, float] = Field(
        default_factory=lambda: dict(DEFAULT_PROVIDER_WEIGHTS)
    )
    default_weight: float = Field(default=0.15, gt=0.0)
    not_found_weight_factor: float = Field(default=0.4, ge=0.0, le=1.0)
    malicious_threshold: float = Field(default=70.0, ge=0.0, le=100.0)
    suspicious_threshold: float = Field(default=30.0, ge=0.0, le=100.0)
    high_signal_score: int = Field(default=70, ge=0, le=100)
    strong_single_source_score: int = Field(default=85, ge=0, le=100)
    corroboration_boost: float = Field(default=10.0, ge=0.0, le=30.0)


def _recommended_action(verdict: Verdict, confidence: ConfidenceLevel) -> str:
    if verdict == Verdict.MALICIOUS:
        if confidence == ConfidenceLevel.HIGH:
            return "Block immediately at perimeter/EDR, hunt lateral movement, and open IR ticket."
        return "Contain or stage block pending analyst validation of single-source high-risk hit."
    if verdict == Verdict.SUSPICIOUS:
        return "Escalate to Tier-2 SOC analyst for SIEM log correlation before blocking."
    if verdict == Verdict.BENIGN:
        return "No containment required; retain telemetry and monitor for behavioral anomalies."
    return "Manual triage required: verify provider API keys/connectivity or pivot in SIEM."


def score_results(
    provider_results: list[ProviderResult],
    policy: ScoringPolicy | None = None,
) -> VerdictAssessment:
    """Compute a deterministic, explainable SOC verdict from normalized provider results."""
    cfg = policy or ScoringPolicy()
    substantive = [
        r for r in provider_results if r.status in (ProviderStatus.OK, ProviderStatus.NOT_FOUND)
    ]

    if not substantive:
        unavailable = [f"{r.provider} ({r.status.value})" for r in provider_results]
        reason = (
            "No Threat Intel provider returned usable telemetry"
            + (f": {', '.join(unavailable)}." if unavailable else ".")
        )
        return VerdictAssessment(
            verdict=Verdict.UNKNOWN,
            composite_score=0.0,
            confidence=ConfidenceLevel.NONE,
            responding_providers=0,
            malicious_providers=0,
            corroborated=False,
            tags=[],
            reasons=[reason],
            recommended_action=_recommended_action(Verdict.UNKNOWN, ConfidenceLevel.NONE),
            evidence=[],
        )

    evidence: list[EvidenceContribution] = []
    reasons: list[str] = []
    tags_set: set[str] = set()

    total_weight = 0.0
    total_points = 0.0
    ok_results: list[ProviderResult] = []
    high_signal_providers: list[ProviderResult] = []
    suspicious_providers: list[ProviderResult] = []
    max_score = 0

    for res in substantive:
        base_weight = cfg.provider_weights.get(res.provider, cfg.default_weight)
        if res.status == ProviderStatus.NOT_FOUND:
            raw_score = 0
            eff_weight = round(base_weight * cfg.not_found_weight_factor, 4)
        else:
            ok_results.append(res)
            raw_score = int(res.malicious_score or 0)
            eff_weight = round(base_weight, 4)
            tags_set.update(res.tags)
            if raw_score > max_score:
                max_score = raw_score
            if raw_score >= cfg.high_signal_score:
                high_signal_providers.append(res)
            if raw_score >= cfg.suspicious_threshold:
                suspicious_providers.append(res)

        weighted_points = round(raw_score * eff_weight, 4)
        total_weight += eff_weight
        total_points += weighted_points

        evidence.append(
            EvidenceContribution(
                provider=res.provider,
                status=res.status,
                raw_score=raw_score,
                effective_weight=eff_weight,
                weighted_points=weighted_points,
                detections=res.detections,
                from_cache=res.from_cache,
            )
        )

        cache_tag = " [cache]" if res.from_cache else ""
        if res.status == ProviderStatus.NOT_FOUND:
            reasons.append(f"{res.provider}: not found in intelligence feed{cache_tag}.")
        else:
            det_info = (
                f", detections={res.detections}/{res.total_engines}"
                if res.total_engines > 0
                else f", detections={res.detections}"
            )
            reasons.append(f"{res.provider}: score={raw_score}/100{det_info}{cache_tag}.")

    weighted_avg = (total_points / total_weight) if total_weight > 0 else 0.0
    composite = weighted_avg
    corroborated = len(high_signal_providers) >= 2

    if corroborated:
        composite = min(100.0, max(weighted_avg, float(max_score)) + cfg.corroboration_boost)
        names = ", ".join(r.provider for r in high_signal_providers)
        reasons.append(
            f"Multi-source corroboration triggered by {len(high_signal_providers)} providers ({names})."
        )
    elif len(high_signal_providers) == 1 and max_score >= cfg.strong_single_source_score:
        composite = max(weighted_avg, cfg.malicious_threshold)
        src = high_signal_providers[0].provider
        reasons.append(
            f"Strong single-source floor applied ({src} score={max_score} >= {cfg.strong_single_source_score})."
        )
    elif len(suspicious_providers) >= 1 and composite < cfg.suspicious_threshold and max_score >= 40:
        composite = max(weighted_avg, cfg.suspicious_threshold)
        names = ", ".join(r.provider for r in suspicious_providers)
        reasons.append(f"Suspicious signal floor applied from {names} (max_score={max_score}).")

    composite = round(max(0.0, min(100.0, composite)), 2)

    if composite >= cfg.malicious_threshold:
        verdict = Verdict.MALICIOUS
        if corroborated:
            confidence = ConfidenceLevel.HIGH
        elif max_score >= cfg.strong_single_source_score:
            confidence = ConfidenceLevel.MEDIUM
        else:
            confidence = ConfidenceLevel.LOW
    elif composite >= cfg.suspicious_threshold:
        verdict = Verdict.SUSPICIOUS
        if len(suspicious_providers) >= 2:
            confidence = ConfidenceLevel.HIGH
        elif len(substantive) >= 2:
            confidence = ConfidenceLevel.MEDIUM
        else:
            confidence = ConfidenceLevel.LOW
    else:
        verdict = Verdict.BENIGN
        if len(substantive) >= 2 and len(ok_results) >= 1:
            confidence = ConfidenceLevel.HIGH
        elif len(substantive) >= 2:
            confidence = ConfidenceLevel.MEDIUM
        else:
            confidence = ConfidenceLevel.LOW

    return VerdictAssessment(
        verdict=verdict,
        composite_score=composite,
        confidence=confidence,
        responding_providers=len(substantive),
        malicious_providers=len(high_signal_providers),
        corroborated=corroborated,
        tags=sorted(tags_set)[:15],
        reasons=reasons,
        recommended_action=_recommended_action(verdict, confidence),
        evidence=evidence,
    )
