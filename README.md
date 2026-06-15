# ASN Karma

ASN Karma is a Go pipeline for building ASN-level risk datasets from observed BlackRoute evidence. It aggregates hostile IP/CIDR records by autonomous system, scores abuse exposure with an auditable rule set, and emits release artifacts for security analytics, fraud/risk enrichment, traffic policy, and network operations.

<p align="center">
  <img src="./site/banner.svg" alt="ASN Karma banner" width="100%">
</p>

<p align="center">
  <a href="./LICENSE"><img alt="License" src="https://img.shields.io/badge/license-Apache%202.0-blue"></a>
  <a href="./.github/workflows/build.yml"><img alt="CI" src="https://img.shields.io/badge/ci-github%20actions-2088FF"></a>
  <img alt="Go" src="https://img.shields.io/badge/go-1.22+-00ADD8">
  <img alt="Dataset" src="https://img.shields.io/badge/dataset-jsonl%20%7C%20csv%20%7C%20txt-informational">
  <img alt="Status" src="https://img.shields.io/badge/status-active-success">
  <img alt="Release" src="https://img.shields.io/badge/release-automated-informational">
</p>

---

## Latest Release

Fresh dataset artifacts are published by the scheduled build. The links below point at the latest GitHub Release assets.

<!-- ASN_KARMA_RELEASE_START -->
_Last dataset build: `2026-06-15T13:36:14Z`_

[Open latest GitHub release](https://github.com/ipanalytics/ASN-Karma/releases/latest)

| Artifact | Download | Description |
| --- | --- | --- |
| `asn-risk.jsonl` | [download](https://github.com/ipanalytics/ASN-Karma/releases/latest/download/asn-risk.jsonl) | Primary JSONL risk dataset |
| `asn-summary.csv` | [download](https://github.com/ipanalytics/ASN-Karma/releases/latest/download/asn-summary.csv) | CSV summary for review and reporting |
| `asn-evidence-table.md` | [download](https://github.com/ipanalytics/ASN-Karma/releases/latest/download/asn-evidence-table.md) | Markdown table of top ASN evidence counts |
| `high-risk-asn-critical.txt` | [download](https://github.com/ipanalytics/ASN-Karma/releases/latest/download/high-risk-asn-critical.txt) | Critical ASN tier |
| `high-risk-asn-high.txt` | [download](https://github.com/ipanalytics/ASN-Karma/releases/latest/download/high-risk-asn-high.txt) | High ASN tier |
| `high-risk-asn-watch.txt` | [download](https://github.com/ipanalytics/ASN-Karma/releases/latest/download/high-risk-asn-watch.txt) | Watch ASN tier |
| `release-notes.md` | [download](https://github.com/ipanalytics/ASN-Karma/releases/latest/download/release-notes.md) | Release summary and top ASN table |
| `run_stats.json` | [download](https://github.com/ipanalytics/ASN-Karma/releases/latest/download/run_stats.json) | Build metadata and tier counts |

<!-- ASN_KARMA_RELEASE_END -->

## Overview

ASN Karma consumes BlackRoute JSONL records and produces an ASN risk layer designed for operational use. The output is intentionally explainable: each ASN record includes score, tier, observed record counts, source diversity, top threat labels, and build metadata.

The project treats ASN expansion as derived intelligence. Source evidence comes from observed IP/CIDR records only; generated ASN prefix lists are output artifacts, not feedback into the evidence stream.

## System Behavior

```text
BlackRoute JSONL
  -> parse observed IP/CIDR evidence
  -> aggregate records by ASN
  -> compute source diversity and threat label distribution
  -> apply scoring policy from configs/scoring.json
  -> write JSONL, CSV, TXT tiers, and run statistics
```

| Stage | Responsibility | Current implementation |
| --- | --- | --- |
| Ingest | Read BlackRoute-style JSONL with tolerant field mapping | `internal/blackroute` |
| Model | Normalize observed records and aggregate by ASN | `internal/model` |
| Scoring | Apply deterministic score and tier policy | `internal/scoring` |
| Output | Emit release artifacts for machines and operators | `internal/output` |
| Automation | Build and publish artifacts from GitHub Actions | `.github/workflows/build.yml` |

## Features

- Go CLI with no runtime service dependency.
- Deterministic ASN scoring from local configuration.
- JSONL primary output for downstream data pipelines.
- CSV summary for analyst workflows.
- Text tier files for infrastructure policy integration.
- GitHub Actions workflow for scheduled dataset builds.
- Explicit `expanded_prefixes_are_evidence: false` field in risk records.
- Local smoke-test fixture under `data/blackroute.example.jsonl`.

## Quick Start

```sh
go test ./...
go run ./cmd/asn-karma \
  -input data/blackroute.example.jsonl \
  -out release \
  -readme README.md
```

The command writes release artifacts into `release/`.

```text
release/
  asn-risk.jsonl
  asn-summary.csv
  asn-evidence-table.md
  high-risk-asn-critical.txt
  high-risk-asn-high.txt
  high-risk-asn-watch.txt
  release-notes.md
  run_stats.json
```

## Installation

### From Source

```sh
git clone https://github.com/ipanalytics/ASN-Karma.git
cd ASN-Karma
go build -o bin/asn-karma ./cmd/asn-karma
```

### Requirements

| Component | Version |
| --- | --- |
| Go | 1.22 or newer |
| Input dataset | BlackRoute JSONL |
| Runtime | Linux, macOS, or containerized CI |

## Usage

Run against a local BlackRoute export:

```sh
asn-karma \
  -input data/blackroute.jsonl \
  -config configs/scoring.json \
  -out release
```

Use a fixed build timestamp for reproducible test output:

```sh
asn-karma \
  -input data/blackroute.example.jsonl \
  -out /tmp/asn-karma-release \
  -built-at 2026-06-15T00:00:00Z
```

Run directly with Go:

```sh
go run ./cmd/asn-karma -input data/blackroute.jsonl -out release
```

## Outputs

| Artifact | Format | Purpose |
| --- | --- | --- |
| `asn-risk.jsonl` | JSONL | Primary machine-readable ASN risk dataset |
| `asn-summary.csv` | CSV | Compact review and reporting table |
| `asn-evidence-table.md` | Markdown | Top ASN evidence table used by README and release notes |
| `high-risk-asn-critical.txt` | TXT | Strict action tier |
| `high-risk-asn-high.txt` | TXT | Challenge or rate-limit tier |
| `high-risk-asn-watch.txt` | TXT | Enrichment and logging tier |
| `release-notes.md` | Markdown | GitHub Release body with run summary and top ASN table |
| `run_stats.json` | JSON | Build metadata and tier counts |

## Latest ASN Evidence

The scheduled build updates this table from the current dataset. `Evidence` is the number of observed BlackRoute records aggregated for the ASN in the active build window. Country is populated when present in upstream records or enrichment data.

<!-- ASN_KARMA_TABLE_START -->
_Last updated: `2026-06-15T13:36:14Z`_

| ASN | Name | Country | Evidence | Sources | Score | Tier |
| --- | --- | --- | ---: | ---: | ---: | --- |
| - | - | - | 0 | 0 | 0 | `none` |

<!-- ASN_KARMA_TABLE_END -->

### Risk Record

```json
{
  "asn": 64500,
  "asn_name": "Example Hosting",
  "country": "US",
  "risk_score": 39,
  "risk_level": "low",
  "recommended_action": "no_action",
  "observed_records": 2,
  "unique_observed_cidrs": 2,
  "source_count": 2,
  "source_diversity": 2,
  "top_threat_labels": {
    "c2_ioc": 1,
    "malware_host_active": 1,
    "network_scan_or_abuse": 1
  },
  "evidence_window_days": 30,
  "persistence_days_30d": 0,
  "expanded_prefix_count": 0,
  "expanded_prefixes_are_evidence": false,
  "large_cloud": false,
  "watchlist": false,
  "built_at": "2026-06-15T00:00:00Z"
}
```

## Scoring Policy

Scoring is configured in `configs/scoring.json`.

| Signal | Role |
| --- | --- |
| Source diversity | Rewards corroboration across feeds |
| Threat severity | Weights labels such as C2, malware hosting, spam, and scanning |
| Recent activity | Captures observed volume in the build window |
| Abuse density proxy | Gives smaller concentrated abuse surfaces weight |
| Cybercrime prefix bonus | Adds weight for severe infrastructure labels |
| Large cloud penalty | Reduces broad-provider overclassification |
| Allowlist penalty | Suppresses known infrastructure where appropriate |
| Watchlist flag | Adds context without turning context into evidence |

Risk tiers are emitted as `critical`, `high`, `watch`, or `low`.

## Operational Notes

- Treat `asn-risk.jsonl` as the canonical artifact.
- Use TXT tier files as policy inputs only after local validation.
- Keep scoring changes reviewable; policy drift should be visible in config diffs.
- Do not feed derived ASN prefix expansion back into source evidence.
- Large cloud and CDN networks need provider-aware handling in production policy.
- Run builds on a schedule after the upstream BlackRoute release has completed.

## Project Scope

ASN Karma focuses on ASN-level aggregation, scoring, and artifact generation. It is designed to sit between raw IP reputation feeds and downstream enforcement, enrichment, or analytics systems.

Planned extension points include:

- Team Cymru bulk IP-to-ASN mapping for records without ASN metadata.
- RIPEstat announced-prefix expansion for derived prefix artifacts.
- Historical persistence windows for 7/30/90 day scoring.
- Signed release checksums.
- GitHub Pages dataset index.

## Use Cases

- Enrich SIEM, SOAR, and data lake events with ASN risk context.
- Feed WAF, CDN, and edge policy with conservative ASN tiers.
- Track abuse concentration across hosting providers and network operators.
- Support fraud and risk pipelines with infrastructure-level features.
- Build daily ASN exposure reports for security operations.

## Limitations

ASN-level scoring is coarse by design. It should be combined with local telemetry, asset context, customer impact analysis, and provider-specific knowledge before enforcement.

The current implementation expects ASN fields in the input JSONL. External IP-to-ASN mapping is an integration target, not a dependency of the core scorer.

## Directory Structure

```text
.
├── cmd/asn-karma/              # CLI entrypoint
├── configs/                    # scoring and policy configuration
├── data/                       # local fixtures and input data
├── internal/blackroute/         # BlackRoute JSONL ingest
├── internal/model/              # normalized records and aggregation
├── internal/output/             # release artifact writers
├── internal/scoring/            # scoring policy implementation
├── release/                     # generated artifacts
├── site/                        # README and documentation assets
└── .github/workflows/           # scheduled build automation
```

## Deployment

The repository includes a scheduled GitHub Actions workflow:

```yaml
on:
  schedule:
    - cron: "47 4 * * *"
  workflow_dispatch:
```

The workflow tests the Go code, downloads the latest BlackRoute JSONL release, builds ASN Karma artifacts, updates the README evidence table, and publishes the generated files as a GitHub release.

For self-hosted deployments, run the CLI from cron, systemd timers, Kubernetes CronJobs, or an existing data orchestration system. The process is batch-oriented and writes immutable output files for each run.

<details>
<summary>Example Kubernetes CronJob command</summary>

```yaml
command:
  - /usr/local/bin/asn-karma
  - -input
  - /data/blackroute.jsonl
  - -config
  - /config/scoring.json
  - -out
  - /release
```

</details>

## License

MIT license.

## Disclaimer

ASN Karma provides infrastructure risk signals derived from public abuse evidence. Operators are responsible for applying local policy, validation, and impact controls before enforcement.
