"""Append-only SHA-256 hash-chained evidence ledger for Threat Intel enrichment."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from vtx_ti_enricher.models import EnrichBatchReport, EnrichedIOC

EVIDENCE_SCHEMA_VERSION = "1.0"
GENESIS_PREV_HASH = "0" * 64
UNKNOWN_ASSET_ID = "unknown-asset"
ASSET_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


class EvidenceRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = EVIDENCE_SCHEMA_VERSION
    seq: int = Field(..., ge=1)
    recorded_at: str
    source: Literal["vtx-ti-enricher"] = "vtx-ti-enricher"
    input_source: str
    asset_id: str
    indicator: str
    defanged: str
    ioc_type: str
    verdict: str
    composite_score: float = Field(default=0.0, ge=0.0, le=100.0)
    confidence: str = "none"
    providers: list[str] = Field(default_factory=list)
    payload_sha256: str = Field(..., min_length=64, max_length=64)
    prev_hash: str = Field(..., min_length=64, max_length=64)
    entry_hash: str = Field(..., min_length=64, max_length=64)


class EvidenceVerificationResult(BaseModel):
    valid: bool
    total_entries: int = 0
    head_hash: str | None = None
    errors: list[str] = Field(default_factory=list)


def normalize_asset_id(asset_id: str | None) -> str:
    if not asset_id:
        return UNKNOWN_ASSET_ID
    cleaned = asset_id.strip().lower()
    if ASSET_ID_RE.match(cleaned):
        return cleaned
    return UNKNOWN_ASSET_ID


def canonical_json(data: dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_sha256_hex(data: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(data).encode("utf-8")).hexdigest()


def _compute_entry_hash(record_without_hash: dict[str, Any]) -> str:
    return compute_sha256_hex(record_without_hash)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def build_evidence_record(
    item: EnrichedIOC,
    *,
    seq: int,
    prev_hash: str,
    input_source: str,
    asset_id: str | None = None,
    recorded_at: str | None = None,
) -> EvidenceRecord:
    assessment = item.assessment
    verdict = assessment.verdict.value if assessment is not None else "unknown"
    composite_score = float(assessment.composite_score) if assessment is not None else 0.0
    confidence = assessment.confidence.value if assessment is not None else "none"
    providers = sorted({res.provider for res in item.provider_results})
    payload_sha256 = compute_sha256_hex(item.model_dump(mode="json"))

    body: dict[str, Any] = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "seq": seq,
        "recorded_at": recorded_at or _utc_now_iso(),
        "source": "vtx-ti-enricher",
        "input_source": input_source,
        "asset_id": normalize_asset_id(asset_id),
        "indicator": item.ioc.value,
        "defanged": item.ioc.defanged,
        "ioc_type": item.ioc.ioc_type.value,
        "verdict": verdict,
        "composite_score": composite_score,
        "confidence": confidence,
        "providers": providers,
        "payload_sha256": payload_sha256,
        "prev_hash": prev_hash,
    }
    entry_hash = _compute_entry_hash(body)
    return EvidenceRecord(**body, entry_hash=entry_hash)


def verify_evidence_log(ledger_path: str | Path) -> EvidenceVerificationResult:
    path = Path(ledger_path)
    if not path.exists():
        return EvidenceVerificationResult(
            valid=False,
            total_entries=0,
            head_hash=None,
            errors=[f"Evidence ledger not found: {path}"],
        )

    errors: list[str] = []
    expected_seq = 1
    expected_prev_hash = GENESIS_PREV_HASH
    head_hash: str | None = None
    total_entries = 0

    raw_lines = path.read_text(encoding="utf-8").splitlines()
    for line_no, raw_line in enumerate(raw_lines, start=1):
        stripped = raw_line.strip()
        if not stripped:
            continue

        try:
            parsed = json.loads(stripped)
            record = EvidenceRecord.model_validate(parsed)
        except (json.JSONDecodeError, ValidationError) as exc:
            errors.append(f"Line {line_no}: invalid evidence record ({exc})")
            continue

        total_entries += 1

        if record.seq != expected_seq:
            errors.append(
                f"Line {line_no}: sequence mismatch (expected {expected_seq}, got {record.seq})"
            )

        if not hmac.compare_digest(record.prev_hash, expected_prev_hash):
            errors.append(
                f"Line {line_no}: prev_hash mismatch (expected {expected_prev_hash}, got {record.prev_hash})"
            )

        body = record.model_dump(mode="json", exclude={"entry_hash"})
        computed_hash = _compute_entry_hash(body)
        if not hmac.compare_digest(computed_hash, record.entry_hash):
            errors.append(
                f"Line {line_no}: entry_hash mismatch (expected {computed_hash}, got {record.entry_hash})"
            )

        expected_prev_hash = record.entry_hash
        head_hash = record.entry_hash
        expected_seq = record.seq + 1

    return EvidenceVerificationResult(
        valid=len(errors) == 0,
        total_entries=total_entries,
        head_hash=head_hash,
        errors=errors,
    )


def append_report_to_evidence_log(
    report: EnrichBatchReport,
    ledger_path: str | Path,
    *,
    asset_id: str | None = None,
) -> list[EvidenceRecord]:
    path = Path(ledger_path)
    next_seq = 1
    prev_hash = GENESIS_PREV_HASH

    if path.exists() and path.stat().st_size > 0:
        check = verify_evidence_log(path)
        if not check.valid:
            details = "; ".join(check.errors[:3])
            raise ValueError(
                f"Refusing to append to corrupted evidence ledger '{path}': {details}"
            )
        next_seq = check.total_entries + 1
        prev_hash = check.head_hash or GENESIS_PREV_HASH

    new_records: list[EvidenceRecord] = []
    for item in report.items:
        rec = build_evidence_record(
            item,
            seq=next_seq,
            prev_hash=prev_hash,
            input_source=report.input_source,
            asset_id=asset_id,
        )
        new_records.append(rec)
        next_seq += 1
        prev_hash = rec.entry_hash

    if not new_records:
        return new_records

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as fh:
        for rec in new_records:
            fh.write(canonical_json(rec.model_dump(mode="json")) + "\n")
        fh.flush()
        os.fsync(fh.fileno())

    return new_records
