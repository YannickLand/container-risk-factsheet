# Delta Experiment results bundle

**Start here → [`REPORT.md`](REPORT.md)** — the self-contained narrative with all results, the baseline definition, every delta, the measurements (determinism, automation ratio, unknown-resolution, latency) and the findings. It is self-contained: all factsheets follow the structure of the repo's `example/factsheet.json`, so the results can be read without running the tool.

## Contents
| file | what it is |
|---|---|
| `REPORT.md` | **key reference** — full narrative + tables + findings |
| `DESIGN_NOTES.md` | design rationale and how the design was calibrated to the tool's behaviour |
| `results_summary.csv` | one row per delta (machine-readable) |
| `hardening_progression.csv` | the bidirectional arc: scenario + per-action levels per step |
| `diffs/<ID>.json` | structured field-level diff vs B0 (incl. assumption-state changes) |
| `runs/<ID>/` | raw `factsheet.json` + `meta.json` (provenance, wall-clock) + exact input copies |
| `determinism_results.csv`, `latency.json` | determinism / latency raw measurements |

All factsheets follow the structure of the repo's `example/factsheet.json`. Numbers in `REPORT.md` are computed from the `runs/` factsheets by `experiment/rollup.py`.
