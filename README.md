# Container Risk Factsheet

A Python tool and REST API for generating **Container Security Risk Factsheets** from Docker Compose files. It analyzes a deployment's security posture by extracting deployment traits, evaluating security assumptions, matching a context scenario, and identifying possible attack actions — all grounded in the [CSRO ontology](https://w3id.org/csro).

## Overview

Given a `docker-compose.yml` file, the tool produces a structured JSON factsheet per service containing:

- **DeploymentTraits** — security-relevant properties detected in the compose file (capabilities, volumes, network, PID mode, etc.)
- **ContainerSecurityAssumptionStates** — satisfaction states (`Satisfied` / `Unknown` / `Dissatisfied`) for 45 CSRO security assumptions
- **MatchingContextScenario** — best-fit deployment scenario (e.g., *Hybrid Cloud Scenario*)
- **PossibleAttackActions** — CSRO attack actions applicable to the matched scenario and current trait set

## Quick Start

### CLI

```bash
# Install (Python 3.12+ required)
pip install -e .

# Generate a factsheet
factsheet generate-factsheet docker-compose.yml -o factsheet.json

# Extract traits only
factsheet extract-traits docker-compose.yml

# Pretty-print JSON output
factsheet generate-factsheet docker-compose.yml --pretty
```

### Docker

```bash
docker compose up
# API available at http://localhost:5004
```

## CLI Reference

### `factsheet generate-factsheet`

```
Usage: factsheet generate-factsheet [OPTIONS] COMPOSE_FILE

  Generate a risk factsheet from a Docker Compose file.

Options:
  -o, --output FILE        Write JSON output to FILE (default: stdout)
  --overrides FILE         YAML file with manual assumption state overrides
  --data-dir DIR           Directory containing risk model data files
  --pretty                 Pretty-print JSON output
  --help                   Show this message and exit.
```

### `factsheet extract-traits`

```
Usage: factsheet extract-traits [OPTIONS] COMPOSE_FILE

  Extract and list deployment traits from a Docker Compose file.

Options:
  --service NAME   Limit output to one service
  --help           Show this message and exit.
```

## REST API

The Flask API server runs on port `5004`.

| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/api/v1/health` | Health check |
| `GET`  | `/api/v1/version` | Version info |
| `POST` | `/api/v1/generate-factsheet` | Generate factsheet (multipart: `compose_file` + optional `overrides`) |
| `POST` | `/api/v1/extract-traits` | Extract traits (multipart: `compose_file`) |

**Example:**

```bash
curl -X POST http://localhost:5004/api/v1/generate-factsheet \
  -F "compose_file=@docker-compose.yml"
```

## Architecture

```
factsheet/               # Core Python package
  compose_normalizer.py  # Canonicalize docker-compose multi-syntax fields
  trait_extractor.py     # Detect security-relevant deployment traits
  risk_model.py          # Load and navigate CSRO knowledge graph
  assumption_evaluator.py# Calculate assumption satisfaction states
  scenario_matcher.py    # Find best-matching context scenario
  factsheet_generator.py # Orchestrate the full pipeline
  cli.py                 # Click CLI entry point

api/                     # Flask REST API
backend/                 # stdlib HTTP backend server
data/                    # Risk model data (JSONLD, schemas, definitions)
tests/                   # pytest test suite (70 tests)
```

## Data Model

The risk model is loaded from:

- `data/tra_model/query_results/15_full_csro/risk_export.jsonld` — CSRO knowledge graph (attack actions, assumptions, scenarios)
- `data/tra_model/query_results/15_full_csro/rule_export.jsonld` — Treatment weights and scoring rules

## Overrides

To manually override an assumption's satisfaction state, create a YAML file:

```yaml
# overrides.yaml
"non-root_user": "Satisfied"
"read_only_root_filesystem": "Satisfied"
```

Pass it to the CLI: `factsheet generate-factsheet compose.yml --overrides overrides.yaml`

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=factsheet --cov-report=html
```

## License

Apache 2.0
