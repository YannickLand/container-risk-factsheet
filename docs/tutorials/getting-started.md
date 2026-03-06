# Getting Started — Your First Factsheet

**What you will learn:** How to install the tool, run it against a Docker Compose file, and read the JSON output.

**Time required:** ~10 minutes.

---

## Prerequisites

- Python 3.12 or later
- A Docker Compose file to analyse

The repository includes a ready-to-use example in the `example/` directory:

| File | What it is |
|------|------------|
| `example/docker-compose.yml` | Single-service Compose file (`analyzer` service with `SYS_PTRACE`, host PID, and an external reverse-proxy network) |
| `example/analyzer.dockerfile` | Dockerfile for that service (Node 18 Alpine, non-root user, pinned packages) |
| `example/assumptions.conf` | Pre-filled set of security assumption overrides for a hardened scenario |

All commands in this tutorial use those files.

---

## Step 1 — Install the package

Create and activate a virtual environment, then install the package in editable mode:

```bash
# Create virtual environment
python -m venv .venv

# Activate (Windows PowerShell)
.venv\Scripts\Activate.ps1

# Activate (macOS / Linux)
source .venv/bin/activate

# Install
pip install -e .
```

Verify the CLI is working:

```bash
factsheet --version
```

---

## Step 2 — Generate your first factsheet

Run the tool against the example Compose file:

```bash
factsheet generate-factsheet example/docker-compose.yml --pretty
```

The output is a JSON object with one key per service.  For the example file you
will see an `analyzer` service:

```json
{
  "analyzer": {
    "DeploymentTraits": [...],
    "ContainerSecurityAssumptionStates": {...},
    "MatchingContextScenario": {...},
    "PossibleAttackActions": [...]
  }
}
```

Save the output to a file for later use:

```bash
factsheet generate-factsheet example/docker-compose.yml -o factsheet.json
```

---

## Step 3 — Understand the output sections

| Section | What it contains |
|---------|-----------------|
| `DeploymentTraits` | Security-relevant properties detected in the Compose file (e.g. `privileged_flag`, `publicly_exposed`) |
| `ContainerSecurityAssumptionStates` | Satisfaction state (`Satisfied` / `Unknown` / `Dissatisfied`) for each of the 45 CSRO security assumptions |
| `MatchingContextScenario` | The best-fit deployment scenario matched from the CSRO knowledge graph |
| `PossibleAttackActions` | Attack actions that are plausible given the current trait set and matched scenario |

---

## Step 4 — Extract only the traits

If you want a quick look at what the tool detects without running the full pipeline:

```bash
factsheet extract-traits example/docker-compose.yml --pretty
```

For the example service you should see traits such as `host_pid`, `cap_add_sys_ptrace`,
`publicly_exposed`, and `external_network` — reflecting the compose configuration.

---

## Step 5 — Generate a treatment report

Once you have a factsheet, generate a prioritised list of remediation actions:

```bash
# First generate the factsheet
factsheet generate-factsheet example/docker-compose.yml -o factsheet.json

# Then produce the treatment report
factsheet treatment-report factsheet.json --pretty
```

The report groups treatments by risk level: **Critical → High → Moderate → Low**.

---

## Next steps

- [How to override assumption states](../how-to-guides/override-assumptions.md) — mark assumptions as already satisfied in your environment
- [How to analyse Dockerfiles](../how-to-guides/analyse-dockerfiles.md) — add static analysis findings to the factsheet
- [CLI Reference](../reference/cli.md) — full list of commands and options
