# CLI Reference

Complete reference for the `factsheet` command-line interface.

---

## Installation

```bash
pip install -e .
factsheet --version
```

If the `factsheet` entrypoint is not on `PATH`, use:
```bash
python -m factsheet.cli <command> ...
```

---

## Global options

| Option | Description |
|--------|-------------|
| `--version` | Show installed version and exit |
| `--help` | Show help message and exit |

---

## `factsheet generate-factsheet`

Generate a security risk factsheet from a Docker Compose file.

```
factsheet generate-factsheet [OPTIONS] COMPOSE_FILE
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `COMPOSE_FILE` | Path to the `docker-compose.yml` file (required) |

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `-o`, `--output FILE` | stdout | Write JSON output to a file |
| `--overrides TEXT\|FILE` | — | Assumption-state overrides as a JSON string, or path to a `.json`, `.yaml`, or `.conf` file |
| `--data-dir DIR` | bundled | Directory containing risk-model data files |
| `--dockerfile FILE` | — | Dockerfile to analyse (repeatable; positional order matches Compose services) |
| `--pretty` | off | Pretty-print JSON output with 2-space indentation |
| `--help` | — | Show this message and exit |

**Override file formats accepted:**

| Extension | Format | Example |
|-----------|--------|---------|
| `.conf` / `.ini` | `KEY=Value` lines, `#` comments | `example/assumptions.conf` |
| `.json` | JSON object | `{"NET-1": "Satisfied"}` |
| `.yaml` / `.yml` | YAML mapping | `NET-1: Satisfied` |

**Example:**

```bash
# Using the bundled example files
factsheet generate-factsheet example/docker-compose.yml \
  --dockerfile example/analyzer.dockerfile \
  --overrides example/assumptions.conf \
  --output factsheet.json \
  --pretty
```

---

## `factsheet extract-traits`

Extract and list deployment traits detected in a Docker Compose file, without running the full factsheet pipeline.

```
factsheet extract-traits [OPTIONS] COMPOSE_FILE
```

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--service NAME` | all | Limit output to a single service |
| `--pretty` | off | Pretty-print JSON |
| `--help` | — | Show this message and exit |

**Example:**

```bash
factsheet extract-traits docker-compose.yml --service web --pretty
```

---

## `factsheet treatment-report`

Generate a prioritised risk treatment report from a previously generated factsheet JSON file.

```
factsheet treatment-report [OPTIONS] FACTSHEET_FILE
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `FACTSHEET_FILE` | Path to a factsheet JSON file produced by `generate-factsheet` |

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `-o`, `--output FILE` | stdout | Write JSON output to a file |
| `--pretty` | off | Pretty-print JSON |
| `--help` | — | Show this message and exit |

**Example:**

```bash
factsheet treatment-report factsheet.json --pretty
```

**Output structure:**

```json
{
  "service_name": {
    "summary": {
      "Critical": 2,
      "High": 3,
      "Moderate": 1,
      "Low": 0,
      "Unknown": 0
    },
    "treatments_by_level": {
      "Critical": [ { "@id": "csro:T_...", ... } ],
      "High": [...]
    },
    "all_treatments": [...]
  }
}
```

---

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error (invalid input, file not found, etc.) |
| 2 | Misuse — bad CLI options or arguments (Click default) |
