# vtx-ti-enricher

[![CI & AppSec Pipeline](https://github.com/ayslans/vtx-ti-enricher/actions/workflows/ci.yml/badge.svg)](https://github.com/ayslans/vtx-ti-enricher/actions/workflows/ci.yml)
![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-3133FF?style=flat)
![STIX 2.1](https://img.shields.io/badge/STIX-2.1-B743FF?style=flat)
![Docker Non-Root](https://img.shields.io/badge/docker-non--root-2496ED?style=flat)
[![Latest Release](https://img.shields.io/github/v/release/ayslans/vtx-ti-enricher?style=flat&color=B743FF)](https://github.com/ayslans/vtx-ti-enricher/releases/latest)
[![License](https://img.shields.io/github/license/ayslans/vtx-ti-enricher?style=flat&color=3133FF)](https://github.com/ayslans/vtx-ti-enricher/blob/main/LICENSE)

Asynchronous Threat Intelligence (TI) and IoC enrichment CLI built with Python, httpx, aiosqlite, pydantic v2, and typer. Designed for Blue Team and SOC pipelines with OPSEC guardrails, bounded concurrency, resilience primitives, deterministic verdict scoring, and STIX 2.1 export.

## Architecture Overview

1. **Refang, Normalization & OPSEC Guard (`parser.py`)**: Extracts and normalizes IPv4, IPv6, domains, URLs, and hashes (MD5, SHA-1, SHA-256). Filters private/RFC1918/internal indicators by default.
2. **Bounded Async Worker Pool (`engine.py`)**: Uses a bounded `asyncio.Queue`, global and per-provider semaphores, and `httpx.AsyncClient` with `follow_redirects=False` (anti-SSRF).
3. **Resilience Primitives (`resilience.py`)**: `AsyncSingleflight` (coalescing), `AsyncCircuitBreaker` (CLOSED/OPEN/HALF_OPEN), and `AsyncTokenBucket` (rate limiting with `Retry-After` feedback).
4. **Providers (`providers.py`)**: AbuseIPDB, AlienVault OTX, URLhaus, and VirusTotal.
5. **WAL SQLite Cache (`cache.py`)**: Persistent `aiosqlite` cache in WAL mode with per-provider TTLs, short negative TTL for `NOT_FOUND`, and no caching for transient errors.
6. **Deterministic Verdict Engine (`scoring.py`)**: Weighted scoring, multi-source corroboration, strong single-source floors, confidence levels, and explainable SOC actions.
7. **STIX 2.1 & SOC Markdown Exporters (`stix_exporter.py`, `markdown_report.py`)**: Deterministic OASIS UUIDv5 STIX 2.1 bundles and severity-prioritized defanged Markdown reports.

## Installation & Local Development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e ".[dev]"
```

### Environment Variables

| Variable | Provider / Usage | Required |
| :--- | :--- | :---: |
| `ABUSEIPDB_API_KEY` | AbuseIPDB API v2 | Optional |
| `VT_API_KEY` | VirusTotal API v3 | Optional |
| `VTX_CACHE_DB` | Default cache path in Docker runtime | Optional |

### Security & Test Checks

```bash
pytest -v
bandit -r src/ -ll -ii
pip-audit --skip-editable
```
## CLI Usage

### `parse` — Extract, normalize, and OPSEC-filter IoCs

```bash
vtx-ti-enricher parse samples/detection_lab_alerts.json --output /tmp/parsed.json
vtx-ti-enricher parse samples/iocs_mixed.txt --include-internal --no-defang
```

### `enrich` — Concurrently enrich IoCs with WAL cache, scoring, STIX 2.1, and Markdown

```bash
vtx-ti-enricher enrich samples/detection_lab_alerts.json \
  --providers otx,urlhaus,abuseipdb,virustotal \
  --concurrency 8 \
  --per-provider-concurrency 4 \
  --rate-limit 5.0 \
  --cache-db .vtx_ti_cache.sqlite3 \
  --output /tmp/enrich-report.json \
  --stix-out /tmp/bundle.stix.json \
  --stix-min-verdict suspicious \
  --md-out /tmp/soc-report.md
```

Useful `enrich` flags:
* `--no-cache`: Bypass the local SQLite cache for the current run.
* `--ttl <seconds>`: Override TTL across enabled providers.
* `--include-internal`: Include private/internal addresses (disabled by default for OPSEC).
* `--defang/--no-defang`: Control indicator defanging in terminal and Markdown output.

### `export` — Convert an existing `EnrichBatchReport` JSON into STIX 2.1 and/or Markdown

```bash
vtx-ti-enricher export /tmp/enrich-report.json \
  --stix-out /tmp/filtered.stix.json \
  --stix-min-verdict malicious \
  --md-out /tmp/soc-report.md
```

### `cache-stats` — Inspect, purge, or clear the WAL cache

```bash
vtx-ti-enricher cache-stats --cache-db .vtx_ti_cache.sqlite3
vtx-ti-enricher cache-stats --cache-db .vtx_ti_cache.sqlite3 --purge
vtx-ti-enricher cache-stats --cache-db .vtx_ti_cache.sqlite3 --clear
```

## Docker Usage

The multi-stage `Dockerfile` installs dependencies in a builder stage and runs the CLI as non-root user `10001:10001` (`vtxapp`) with a writable cache directory at `/var/lib/vtx-ti-enricher`.

```bash
docker build --target runtime -t vtx-ti-enricher:local .
docker run --rm vtx-ti-enricher:local version

docker run --rm \
  -e ABUSEIPDB_API_KEY="${ABUSEIPDB_API_KEY:-}" \
  -e VT_API_KEY="${VT_API_KEY:-}" \
  -v "$(pwd)/samples:/data/samples:ro" \
  -v "$(pwd)/out:/data/out" \
  vtx-ti-enricher:local \
  enrich /data/samples/detection_lab_alerts.json \
    --providers otx,urlhaus \
    --cache-db /var/lib/vtx-ti-enricher/cache.sqlite3 \
    --stix-out /data/out/bundle.stix.json \
    --md-out /data/out/soc-report.md
```
