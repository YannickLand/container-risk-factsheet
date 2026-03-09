# Container Risk Factsheet

[![CI](https://github.com/YannickLand/container-risk-factsheet/actions/workflows/ci.yml/badge.svg)](https://github.com/YannickLand/container-risk-factsheet/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/YannickLand/container-risk-factsheet/branch/main/graph/badge.svg)](https://codecov.io/gh/YannickLand/container-risk-factsheet)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.18925002.svg)](https://doi.org/10.5281/zenodo.18925002)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A Python tool and REST API for generating **Container Security Risk Factsheets** from Docker Compose files.  It analyses a deployment's security posture by extracting deployment traits, evaluating security assumptions, matching a context scenario, and identifying possible attack actions — all grounded in the [CSRO ontology](https://w3id.org/csro).

---

## What it does

Given a `docker-compose.yml` file, the tool produces a structured JSON factsheet per service:

| Output section | Content |
|----------------|---------|
| `DeploymentTraits` | Security-relevant properties detected in the Compose file and optional Dockerfiles |
| `ContainerSecurityAssumptionStates` | Satisfaction states (`Satisfied` / `Unknown` / `Dissatisfied`) for 45 CSRO assumptions |
| `MatchingContextScenario` | Best-fit deployment scenario (e.g. *Hybrid Cloud*) |
| `PossibleAttackActions` | CSRO attack actions applicable to the matched scenario and current trait set |

A separate **treatment report** command groups risk remediation actions by severity (Critical → High → Moderate → Low).

---

## Quick start

```bash
# Python 3.12+ required
python -m venv .venv
.venv\Scripts\Activate.ps1   # Windows
source .venv/bin/activate    # macOS / Linux

pip install -e .

# Generate a factsheet
factsheet generate-factsheet docker-compose.yml --pretty

# Extract deployment traits only
factsheet extract-traits docker-compose.yml --pretty

# Generate a prioritised treatment report
factsheet generate-factsheet docker-compose.yml -o factsheet.json
factsheet treatment-report factsheet.json --pretty

# Include Dockerfile static analysis (requires hadolint)
factsheet generate-factsheet docker-compose.yml --dockerfile Dockerfile --pretty

# Override assumption states
factsheet generate-factsheet docker-compose.yml \
  --overrides '{"NET-1":"Satisfied","IMG":"Satisfied"}' --pretty
```

**Docker (API server):**
```bash
docker compose up
# Swagger UI: http://localhost:5004/api/docs
```

---

## Documentation

| | |
|---|---|
| **Tutorial** | [Getting Started — your first factsheet](docs/tutorials/getting-started.md) |
| **How-to** | [Override assumption states](docs/how-to-guides/override-assumptions.md) |
| **How-to** | [Analyse Dockerfiles with Hadolint](docs/how-to-guides/analyse-dockerfiles.md) |
| **Reference** | [CLI commands](docs/reference/cli.md) |
| **Reference** | [REST API endpoints](docs/reference/rest-api.md) |
| **Explanation** | [How factsheet generation works](docs/explanation/how-factsheets-work.md) |

---

## REST API

Start the server with `docker compose up` or `python -m api.api_server`.  
Interactive Swagger UI: **`http://localhost:5004/api/docs`**

| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/api/v1/health` | Liveness check |
| `GET`  | `/api/v1/version` | Version info |
| `POST` | `/api/v1/generate-factsheet` | Generate factsheet (`compose_file` + optional `overrides`, `dockerfile_N`) |
| `POST` | `/api/v1/extract-traits` | Extract deployment traits (`compose_file`) |
| `POST` | `/api/v1/generate-treatment-report` | Generate treatment report (`compose_file` + optional fields) |

```bash
curl -X POST http://localhost:5004/api/v1/generate-factsheet \
  -F "compose_file=@docker-compose.yml" \
  -F 'overrides={"NET-1":"Satisfied"}'
```

---

## Architecture

```
factsheet/               # Core Python package
  compose_normalizer.py  # Canonicalise docker-compose multi-syntax fields
  trait_extractor.py     # Detect security-relevant deployment traits
  dockerfile_analyzer.py # Hadolint-based Dockerfile static analysis
  risk_model.py          # Load and navigate CSRO knowledge graph
  assumption_evaluator.py# Calculate assumption satisfaction states
  scenario_matcher.py    # Find best-matching context scenario
  factsheet_generator.py # Orchestrate the full pipeline
  treatment_report.py    # Extract and group risk treatments
  cli.py                 # Click CLI entry point

api/                     # Flask REST API + Swagger UI (flasgger)
  swagger_specs/         # Per-endpoint OpenAPI YAML specs
backend/                 # stdlib HTTP backend server
data/                    # Risk model data (JSON-LD, schemas)
tests/                   # pytest test suite (113 tests)
docs/                    # Diataxis documentation
```

---

## Development

```bash
pip install -e ".[dev]"

# Run unit tests (fast, no external tools required)
pytest -m "not integration"

# Run all tests including integration (requires hadolint)
pytest

# Run with coverage
pytest --cov=factsheet --cov=api --cov-report=html
```

---

## License

[MIT](LICENSE)
