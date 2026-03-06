# How to Analyse Dockerfiles

**Goal:** Include static analysis findings from [Hadolint](https://github.com/hadolint/hadolint) in the factsheet so that Dockerfile-level security issues are reflected as deployment traits.

---

## Prerequisites

Install Hadolint on your machine.  The tool works without it — if the binary is absent, the pipeline silently skips Dockerfile analysis and emits only a `dockerfile_analyzed` trait marking the tool as unavailable.

**macOS (Homebrew):**
```bash
brew install hadolint
```

**Linux:**
```bash
curl -sSL \
  "https://github.com/hadolint/hadolint/releases/download/v2.12.0/hadolint-Linux-x86_64" \
  -o /usr/local/bin/hadolint
chmod +x /usr/local/bin/hadolint
```

**Windows (Scoop):**
```powershell
scoop install hadolint
```

Verify: `hadolint --version`

---

## CLI

Supply Dockerfiles with `--dockerfile`.  The flag is positional — the first `--dockerfile` maps to the first service in `docker-compose.yml`, the second to the second service, and so on.

The repository includes `example/analyzer.dockerfile` (Node 18 Alpine, non-root user,
pinned `apk` packages) to try this immediately:

```bash
# Run against the example Compose file + its Dockerfile
factsheet generate-factsheet example/docker-compose.yml \
  --dockerfile example/analyzer.dockerfile \
  --pretty
```

For a multi-service Compose file, pass one `--dockerfile` per service in order:

```bash
factsheet generate-factsheet docker-compose.yml \
  --dockerfile services/web/Dockerfile \
  --dockerfile services/db/Dockerfile \
  --pretty
```

---

## REST API

Send Dockerfiles as additional form-data fields named `dockerfile_0`, `dockerfile_1`, …:

```bash
curl -X POST http://localhost:5004/api/v1/generate-factsheet \
  -F "compose_file=@example/docker-compose.yml" \
  -F "dockerfile_0=@example/analyzer.dockerfile"
```

---

## How traits are produced

For each Dockerfile:

1. Hadolint runs and returns findings in JSON format.
2. Findings are grouped by rule ID and deduplicated.
3. Each distinct rule produces one trait (e.g. `dockerfile_latest_tag` for DL3007).
4. A `dockerfile_analyzed` summary trait is always added.
5. If there are zero findings, a `dockerfile_no_findings` trait is added.

### Trait example

```json
{
  "id": "dockerfile_latest_tag",
  "name": "dockerfile_latest_tag",
  "source": "dockerfile",
  "sourceDetails": {
    "service": "web",
    "tool": "hadolint",
    "rule_id": "DL3007",
    "occurrences": 1,
    "lines": [1],
    "severity": "warning",
    "evidence": ["Line 1: Using latest is best avoided"]
  },
  "type": "dockerfile_analysis"
}
```

### Rule to trait mapping (selected)

| Hadolint rule | Trait ID | Issue |
|---------------|----------|-------|
| DL3002 | `dockerfile_root_user` | Container runs as root |
| DL3007 | `dockerfile_latest_tag` | `FROM` uses `:latest` tag |
| DL3020 | `dockerfile_add_vs_copy` | `ADD` used instead of `COPY` |
| DL3008 | `dockerfile_unpinned_packages` | Unpinned `apt-get` packages |
| DL4006 | `dockerfile_pipefail_missing` | Missing `set -o pipefail` |

See `factsheet/dockerfile_analyzer.py` (`_RULE_TO_TRAIT` dict) for the full mapping.

---

## Checking the result

Generated Dockerfile traits appear in `DeploymentTraits` alongside Compose-derived traits.  They are identifiable by `"source": "dockerfile"`.
