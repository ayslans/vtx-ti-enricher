# vtx-ti-enricher

Asynchronous Threat Intelligence & IOC enrichment engine for Blue Team and SOC pipelines, built to ingest alerts from `vtx-detection-lab`, prevent internal-IP OPSEC leakage, enrich indicators concurrently, and export deterministic verdicts and STIX 2.1 bundles.

## Quickstart

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest -v
vtx-ti-enricher parse samples/iocs_mixed.txt
vtx-ti-enricher parse samples/detection_lab_alerts.json
