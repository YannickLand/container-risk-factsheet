# Delta Experiment

A reproducible demonstration that the Container Risk Factsheet tool **re-derives factsheets
deterministically, selectively, and responsively** when a deployment or the knowledge base
changes. It changes one thing at a time (a *delta*) — a Compose/Dockerfile edit, an
`assumptions.conf` change, or a knowledge-base edit — and records how the generated factsheet
moves.

The single running example is a loosely-configured container (`pid: host` + `cap_add: SYS_PTRACE`,
a host `/var` volume, an external network) that yields four attack actions. From that baseline,
the deltas move the assessed risk **both ways**: verifying security controls as *present* hardens
the posture and lowers risk; verifying them *absent* raises it.

## Start here

- **[`results/REPORT.md`](results/REPORT.md)** — the key reference: full narrative, baseline
  definition, every delta, the measurements (determinism, automation ratio, unknown-resolution,
  latency) and the findings. Self-contained; readable without running anything.
- **[`DESIGN_NOTES.md`](DESIGN_NOTES.md)** — design rationale and how the design was calibrated
  to the tool's actual behaviour.
- **[`results/`](results/)** — the portable result bundle (CSVs, per-delta diffs, raw runs).

## The deltas (all single-variable, vs the baseline B0)

| delta | change | direction |
|---|---|---|
| `HARDEN_ARTEFACT` | Compose: run as non-root **and** `cap_drop: ALL` | harden (recorded, no level change) |
| `HARDEN_TECH` | `assumptions.conf`: technical control families = Satisfied | harden → risk down |
| `HARDEN_FULL` | `assumptions.conf`: all families = Satisfied | harden → risk down |
| `DEGRADE_TECH` | `assumptions.conf`: technical control families = Dissatisfied | degrade → risk up |
| `DEGRADE_BREACH` | `assumptions.conf`: all families = Dissatisfied | degrade → risk up |
| `REMOVE_VOLUME` | Compose: remove the `/var` host volume | selective risk removal |
| `KB_IMPACT` | knowledge base: raise one impact rating | knowledge-level change |

## Reproduce

Requires Docker. From the **repository root**:

```bash
docker compose build api          # builds the tool image (bundles hadolint)
bash experiment/run_all.sh        # baseline + all deltas, each a separate `docker run`
bash experiment/determinism.sh    # determinism check across separate invocations
python experiment/rollup.py       # regenerate results/ (REPORT.md, CSVs, diffs)
```

Each run is a separate `docker run` of the image's `factsheet` CLI, so determinism is tested
across separate processes and the knowledge-base delta swaps in an edited KB copy via `--data-dir`.

## Layout

```
experiment/
  README.md            ← you are here
  DESIGN_NOTES.md      design rationale + calibration
  run_all.sh           run baseline + all deltas (Docker)
  determinism.sh       determinism check (Docker)
  rollup.py            build the results/ bundle
  analyze.py           summarise / hash / diff a factsheet
  simulate.py          in-process scenario-selection explorer (no Docker)
  inputs/<DELTA>/      exact inputs per run (compose, dockerfile, assumptions.conf)
  kb/d6_data/          edited knowledge-base copy used by KB_IMPACT
  runs/<DELTA>/        raw factsheet.json + meta.json + input copies
  results/             portable bundle — START at results/REPORT.md
```
