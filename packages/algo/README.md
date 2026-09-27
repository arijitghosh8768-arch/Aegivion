# Aegivion

Autonomous Explainable Cloud Security Copilot.

## Detection Engineering

**Algorithm #1 — Cloud Credential Compromise Detector** is implemented in
`detection/credential_compromise/`. Start with its
[README](detection/credential_compromise/README.md), which explains every
component, the pipeline, the configuration system and the security constraints.

Current status: **Part 1 (foundation)** — CloudTrail normalization, identity
resolution, session construction, identity profiles, configuration and storage,
with unit tests and fixtures. Behavioral features, rules, baselines, anomaly
detection, risk fusion and finding generation are Part 2.

## Layout

```
detection/credential_compromise/   Algorithm #1 (Sentinel Detection Engine)
ingestion/aws/                     CloudTrail ingestion + IP enrichment seam
storage/                           PostgreSQL/SQLite models and repositories
api/                               HTTP API surface
```

## Setup

```bash
python -m pip install -r requirements.txt
python -m pytest detection -q
```
