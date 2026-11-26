# ADR-0001: Python asyncio Architecture for Threat Intelligence Enrichment

* **Status:** Accepted
* **Date:** 2026-11-26

## Context
`vtx-ti-enricher` enriches IOCs extracted from `vtx-detection-lab` alerts against external Threat Intelligence APIs (AbuseIPDB, OTX, URLhaus, VirusTotal). The workload is I/O-bound with rate limits and retries.

## Decision
Implement the engine in Python 3.11+ using `asyncio`, `httpx.AsyncClient`, `aiosqlite`, and `Pydantic v2`.

## Mitigations for Accepted Technical Debt
* **Container footprint:** Multi-stage `python:3.12-slim` non-root image stripping `pip`, `setuptools`, and `wheel`.
* **SCA surface:** Minimal dependencies gated by `pip-audit`, Trivy SARIF, and weekly Dependabot.
* **Event-loop safety:** Strictly async I/O validated with `pytest-asyncio` and `respx`.
