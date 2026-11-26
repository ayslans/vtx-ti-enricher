"""Deterministic STIX 2.1 bundle exporter (zero external dependencies, OASIS UUIDv5)."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vtx_ti_enricher import __version__
from vtx_ti_enricher.models import (
    ConfidenceLevel,
    EnrichBatchReport,
    EnrichedIOC,
    IOCRecord,
    IOCType,
    Verdict,
    VerdictAssessment,
)
from vtx_ti_enricher.scoring import score_results

# Official OASIS STIX 2.1 namespace for deterministic Cyber-observable Object (SCO) IDs
STIX_OASIS_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
VTX_STIX_NAMESPACE = uuid.uuid5(STIX_OASIS_NAMESPACE, "vortexai:vtx-ti-enricher:stix21")

_STIX_HASH_ALGO: dict[IOCType, str] = {
    IOCType.MD5: "MD5",
    IOCType.SHA1: "SHA-1",
    IOCType.SHA256: "SHA-256",
}

_VERDICT_RANK: dict[Verdict, int] = {
    Verdict.UNKNOWN: 0,
    Verdict.BENIGN: 1,
    Verdict.SUSPICIOUS: 2,
    Verdict.MALICIOUS: 3,
}

_VERDICT_INDICATOR_TYPES: dict[Verdict, list[str]] = {
    Verdict.MALICIOUS: ["malicious-activity"],
    Verdict.SUSPICIOUS: ["anomalous-activity"],
    Verdict.BENIGN: ["benign"],
    Verdict.UNKNOWN: ["unknown"],
}

_CONFIDENCE_TO_STIX: dict[ConfidenceLevel, int] = {
    ConfidenceLevel.HIGH: 85,
    ConfidenceLevel.MEDIUM: 60,
    ConfidenceLevel.LOW: 30,
    ConfidenceLevel.NONE: 0,
}


def format_stix_timestamp(dt: datetime | None = None) -> str:
    """Format a UTC datetime into STIX 2.1 RFC 3339 millisecond precision string."""
    target = dt.astimezone(timezone.utc) if dt is not None else datetime.now(timezone.utc)
    return target.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def escape_stix_pattern_value(value: str) -> str:
    """Escape backslashes and single quotes per STIX 2.1 Section 9 patterning rules."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _deterministic_id(
    stix_type: str,
    seed: str,
    namespace: uuid.UUID = VTX_STIX_NAMESPACE,
) -> str:
    return f"{stix_type}--{uuid.uuid5(namespace, f'{stix_type}:{seed}')}"


def build_stix_pattern(ioc: IOCRecord) -> str:
    """Build a valid STIX 2.1 indicator pattern for any supported IOCType."""
    escaped = escape_stix_pattern_value(ioc.value)
    if ioc.ioc_type == IOCType.IPV4:
        return f"[ipv4-addr:value = '{escaped}']"
    if ioc.ioc_type == IOCType.IPV6:
        return f"[ipv6-addr:value = '{escaped}']"
    if ioc.ioc_type == IOCType.DOMAIN:
        return f"[domain-name:value = '{escaped}']"
    if ioc.ioc_type == IOCType.URL:
        return f"[url:value = '{escaped}']"
    algo = _STIX_HASH_ALGO[ioc.ioc_type]
    return f"[file:hashes.'{algo}' = '{escaped}']"


def build_sco(ioc: IOCRecord) -> dict[str, Any]:
    """Build a deterministic STIX 2.1 Cyber-observable Object (SCO) using OASIS UUIDv5."""
    if ioc.ioc_type == IOCType.IPV4:
        stix_type, contrib = "ipv4-addr", {"value": ioc.value}
    elif ioc.ioc_type == IOCType.IPV6:
        stix_type, contrib = "ipv6-addr", {"value": ioc.value}
    elif ioc.ioc_type == IOCType.DOMAIN:
        stix_type, contrib = "domain-name", {"value": ioc.value}
    elif ioc.ioc_type == IOCType.URL:
        stix_type, contrib = "url", {"value": ioc.value}
    else:
        stix_type = "file"
        contrib = {"hashes": {_STIX_HASH_ALGO[ioc.ioc_type]: ioc.value}}

    canonical = json.dumps(contrib, sort_keys=True, separators=(",", ":"))
    sco_id = f"{stix_type}--{uuid.uuid5(STIX_OASIS_NAMESPACE, canonical)}"
    return {
        "type": stix_type,
        "spec_version": "2.1",
        "id": sco_id,
        **contrib,
    }


def build_producer_identity(
    timestamp: str,
    producer_name: str = "vtx-ti-enricher (Blue Team SOC Pipeline)",
) -> dict[str, Any]:
    """Build the deterministic STIX 2.1 Identity SDO representing this enrichment engine."""
    return {
        "type": "identity",
        "spec_version": "2.1",
        "id": _deterministic_id("identity", producer_name),
        "created": timestamp,
        "modified": timestamp,
        "name": producer_name,
        "identity_class": "system",
        "description": f"Automated Threat Intelligence enrichment engine v{__version__}.",
    }


def _resolve_assessment(item: EnrichedIOC) -> VerdictAssessment:
    if item.assessment is not None:
        return item.assessment
    return score_results(item.provider_results)


def export_stix_bundle(
    report: EnrichBatchReport,
    min_verdict: Verdict | None = None,
    generated_at: datetime | None = None,
    producer_name: str = "vtx-ti-enricher (Blue Team SOC Pipeline)",
) -> dict[str, Any]:
    """Convert an EnrichBatchReport into a deterministic STIX 2.1 Bundle dictionary."""
    timestamp = format_stix_timestamp(generated_at)
    identity = build_producer_identity(timestamp=timestamp, producer_name=producer_name)
    identity_id = str(identity["id"])

    objects: list[dict[str, Any]] = [identity]
    seen_ids: set[str] = {identity_id}
    min_rank = _VERDICT_RANK[min_verdict] if min_verdict is not None else -1

    sorted_items = sorted(
        report.items,
        key=lambda x: (x.ioc.ioc_type.value, x.ioc.value),
    )

    for item in sorted_items:
        assessment = _resolve_assessment(item)
        if _VERDICT_RANK[assessment.verdict] < min_rank:
            continue

        ioc = item.ioc
        sco = build_sco(ioc)
        sco_id = str(sco["id"])
        pattern = build_stix_pattern(ioc)

        ind_seed = f"{ioc.ioc_type.value}:{ioc.value}:{assessment.verdict.value}"
        indicator_id = _deterministic_id("indicator", ind_seed)

        labels = sorted(
            set(assessment.tags)
            | {
                f"verdict:{assessment.verdict.value}",
                f"confidence:{assessment.confidence.value}",
            }
        )
        description_parts = list(assessment.reasons)
        description_parts.append(f"Recommended action: {assessment.recommended_action}")

        indicator: dict[str, Any] = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created_by_ref": identity_id,
            "created": timestamp,
            "modified": timestamp,
            "name": f"[{assessment.verdict.value.upper()}] {ioc.defanged}",
            "description": " ".join(description_parts),
            "indicator_types": _VERDICT_INDICATOR_TYPES[assessment.verdict],
            "pattern": pattern,
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": timestamp,
            "confidence": _CONFIDENCE_TO_STIX[assessment.confidence],
            "labels": labels,
            "x_vtx_verdict": assessment.verdict.value,
            "x_vtx_composite_score": assessment.composite_score,
            "x_vtx_corroborated": assessment.corroborated,
            "x_vtx_recommended_action": assessment.recommended_action,
            "x_vtx_sources": list(ioc.sources),
        }

        rel_id = _deterministic_id("relationship", f"{indicator_id}:based-on:{sco_id}")
        relationship: dict[str, Any] = {
            "type": "relationship",
            "spec_version": "2.1",
            "id": rel_id,
            "created_by_ref": identity_id,
            "created": timestamp,
            "modified": timestamp,
            "relationship_type": "based-on",
            "source_ref": indicator_id,
            "target_ref": sco_id,
            "description": f"Indicator derived from normalized {ioc.ioc_type.value} observable.",
        }

        sighting_count = max(1, len(ioc.sources))
        sighting_id = _deterministic_id(
            "sighting",
            f"{indicator_id}:{identity_id}:{report.input_source}",
        )
        sighting: dict[str, Any] = {
            "type": "sighting",
            "spec_version": "2.1",
            "id": sighting_id,
            "created_by_ref": identity_id,
            "created": timestamp,
            "modified": timestamp,
            "first_seen": timestamp,
            "last_seen": timestamp,
            "count": sighting_count,
            "sighting_of_ref": indicator_id,
            "where_sighted_refs": [identity_id],
            "summary": False,
            "description": (
                f"Observed in {report.input_source} "
                f"({sighting_count} source reference(s); "
                f"{assessment.responding_providers} responding TI provider(s))."
            ),
        }

        for obj in (sco, indicator, relationship, sighting):
            obj_id = str(obj["id"])
            if obj_id not in seen_ids:
                seen_ids.add(obj_id)
                objects.append(obj)

    bundle_seed = "|".join(str(o["id"]) for o in objects)
    return {
        "type": "bundle",
        "id": _deterministic_id("bundle", bundle_seed),
        "objects": objects,
    }


def write_stix_bundle(
    report: EnrichBatchReport,
    output_path: Path,
    min_verdict: Verdict | None = None,
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    """Serialize a deterministic STIX 2.1 Bundle to disk as formatted UTF-8 JSON."""
    bundle = export_stix_bundle(
        report=report,
        min_verdict=min_verdict,
        generated_at=generated_at,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(bundle, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return bundle
