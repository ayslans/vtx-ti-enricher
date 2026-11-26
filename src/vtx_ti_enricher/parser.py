"""IOC extraction, refanging, defanging, OPSEC filtering, and detection-lab ingestion."""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from vtx_ti_enricher.models import IOCRecord, IOCType, ParseReport, ParseSummary

_INTERNAL_V4 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("0.0.0.0/8"),
)
_INTERNAL_V6 = (
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)
_DOC_NETS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)
_HEX_RE = re.compile(r"^[a-fA-F0-9]+$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)
_INTERNAL_TLDS = (".local", ".internal", ".lan", ".corp", ".home", ".localhost")
_ALERT_IOC_KEYS = {
    "src_ip", "source_ip", "dest_ip", "dst_ip", "ip", "remote_ip",
    "domain", "hostname", "query", "url", "uri",
    "sha256", "sha1", "md5", "file_hash", "hash", "ioc", "indicator",
}


def refang(raw: str) -> str:
    text = raw.strip().strip("\"'`,;<>()")
    text = re.sub(r"^hxxps", "https", text, flags=re.IGNORECASE)
    text = re.sub(r"^hxxp", "http", text, flags=re.IGNORECASE)
    text = text.replace("[:]", ":").replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    return text.replace("[@]", "@").replace("(@)", "@").replace("[/]", "/").strip()


def defang(value: str, ioc_type: IOCType) -> str:
    if ioc_type in (IOCType.IPV4, IOCType.DOMAIN):
        return value.replace(".", "[.]")
    if ioc_type == IOCType.IPV6:
        return value.replace(":", "[:]")
    if ioc_type == IOCType.URL:
        parsed = urlparse(value)
        scheme = parsed.scheme.lower().replace("http", "hxxp", 1)
        host = (parsed.hostname or "").replace(".", "[.]")
        port = f":{parsed.port}" if parsed.port else ""
        query = f"?{parsed.query}" if parsed.query else ""
        return f"{scheme}://{host}{port}{parsed.path or ''}{query}"
    return value


def _classify_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> tuple[bool, bool]:
    if any(ip_obj in net for net in _DOC_NETS):
        return False, True
    nets = _INTERNAL_V4 if ip_obj.version == 4 else _INTERNAL_V6
    return any(ip_obj in net for net in nets) or ip_obj.is_multicast, False


def classify_indicator(raw_value: str, source: str = "input") -> IOCRecord | None:
    candidate = refang(raw_value)
    if not candidate or len(candidate) > 2048:
        return None

    if candidate.lower().startswith(("http://", "https://")):
        parsed = urlparse(candidate)
        host = (parsed.hostname or "").lower()
        if not host:
            return None
        is_internal = host == "localhost" or host.endswith(_INTERNAL_TLDS)
        is_doc = False
        try:
            is_internal, is_doc = _classify_ip(ipaddress.ip_address(host))
        except ValueError:
            if not _DOMAIN_RE.match(host) and host != "localhost":
                return None
        port = f":{parsed.port}" if parsed.port else ""
        query = f"?{parsed.query}" if parsed.query else ""
        normalized = f"{parsed.scheme.lower()}://{host}{port}{parsed.path or ''}{query}"
        return IOCRecord(
            ioc_type=IOCType.URL,
            value=normalized,
            defanged=defang(normalized, IOCType.URL),
            is_internal=is_internal,
            is_documentation=is_doc,
            sources=[source],
        )

    try:
        ip_obj = ipaddress.ip_address(candidate)
        ioc_type = IOCType.IPV4 if ip_obj.version == 4 else IOCType.IPV6
        canonical = str(ip_obj)
        is_internal, is_doc = _classify_ip(ip_obj)
        return IOCRecord(
            ioc_type=ioc_type,
            value=canonical,
            defanged=defang(canonical, ioc_type),
            is_internal=is_internal,
            is_documentation=is_doc,
            sources=[source],
        )
    except ValueError:
        pass

    if _HEX_RE.match(candidate):
        hash_map = {64: IOCType.SHA256, 40: IOCType.SHA1, 32: IOCType.MD5}
        if len(candidate) in hash_map:
            canonical = candidate.lower()
            return IOCRecord(
                ioc_type=hash_map[len(candidate)],
                value=canonical,
                defanged=canonical,
                sources=[source],
            )

    domain = candidate.lower().rstrip(".")
    if _DOMAIN_RE.match(domain):
        return IOCRecord(
            ioc_type=IOCType.DOMAIN,
            value=domain,
            defanged=defang(domain, IOCType.DOMAIN),
            is_internal=domain.endswith(_INTERNAL_TLDS),
            sources=[source],
        )
    return None


def _extract_from_json_node(node: Any, context: str, extracted: list[tuple[str, str]]) -> None:
    if isinstance(node, dict):
        alert_ref = node.get("rule_id") or node.get("alert_id") or node.get("id")
        local_ctx = f"{context}:{alert_ref}" if alert_ref else context
        for key, val in node.items():
            if isinstance(val, str) and str(key).lower() in _ALERT_IOC_KEYS:
                extracted.append((val, f"{local_ctx}.{key}"))
            elif isinstance(val, (dict, list)):
                _extract_from_json_node(val, f"{local_ctx}.{key}", extracted)
    elif isinstance(node, list):
        for idx, item in enumerate(node):
            if isinstance(item, str):
                extracted.append((item, f"{context}[{idx}]"))
            elif isinstance(item, (dict, list)):
                _extract_from_json_node(item, f"{context}[{idx}]", extracted)


def parse_candidates(
    candidates: list[tuple[str, str]],
    input_source: str,
    include_internal: bool = False,
) -> ParseReport:
    valid_map: dict[tuple[IOCType, str], IOCRecord] = {}
    internal_map: dict[tuple[IOCType, str], IOCRecord] = {}
    invalid_count = 0

    for raw_val, src in candidates:
        record = classify_indicator(raw_val, source=src)
        if record is None:
            invalid_count += 1
            continue
        key = (record.ioc_type, record.value)
        target = internal_map if (record.is_internal and not include_internal) else valid_map
        if key in target:
            if src not in target[key].sources:
                target[key].sources.append(src)
        else:
            target[key] = record

    indicators = sorted(valid_map.values(), key=lambda r: (r.ioc_type.value, r.value))
    internal_indicators = sorted(internal_map.values(), key=lambda r: (r.ioc_type.value, r.value))
    by_type: dict[str, int] = {}
    for rec in indicators:
        by_type[rec.ioc_type.value] = by_type.get(rec.ioc_type.value, 0) + 1

    return ParseReport(
        input_source=input_source,
        summary=ParseSummary(
            total_candidates=len(candidates),
            unique_valid=len(indicators),
            skipped_internal=len(internal_indicators),
            invalid_ignored=invalid_count,
            by_type=by_type,
        ),
        indicators=indicators,
        internal_indicators=internal_indicators,
    )


def parse_file(path: Path, include_internal: bool = False) -> ParseReport:
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")
    raw_text = path.read_text(encoding="utf-8")
    candidates: list[tuple[str, str]] = []
    if path.suffix.lower() == ".json":
        _extract_from_json_node(json.loads(raw_text), path.name, candidates)
    else:
        for line_no, line in enumerate(raw_text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            for token in re.split(r"[\s,]+", stripped):
                if token:
                    candidates.append((token, f"{path.name}:L{line_no}"))
    return parse_candidates(candidates, str(path), include_internal=include_internal)
