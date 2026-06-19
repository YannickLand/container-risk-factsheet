# Delta Experiment — Design Notes

How the experiment is designed and why, and how the design was calibrated to the tool's
actual behaviour. For the results themselves see [`results/REPORT.md`](results/REPORT.md).

The experiment runs against the **Dockerised tool image** built from `docker-compose.yml`
(`container-risk-factsheet-api:latest`, which bundles hadolint v2.12.0). Each run is a
**separate `docker run`** of the image's `factsheet` CLI — so determinism is tested across
*separate processes* (not iterations in one process), the knowledge-base swap is clean
(`--data-dir`), and container start-up is separable from analysis time. The live API server
(`docker compose up` → `POST /api/v1/generate-factsheet`) uses the identical in-process path
and was verified to produce a byte-identical factsheet for B0.

## Tool causal model (confirmed from source + runs)
1. Traits ← Compose (+ Dockerfile via hadolint).
2. Assumption states ← trait verifiers, overridable by `assumptions.conf`.
3. **Context scenario** ← best score of the assumption profile against 22 scenarios.
4. Attack actions ← the chosen scenario's instances whose technique `requiresTrait` are present.
5. Ratings (exploitability/exposure/likelihood/risk/impact) are **static per-scenario values
   baked into the KB** — not recomputed from traits.

**Consequences (decisive):** per-action ratings move ONLY when the selected scenario changes;
the action SET moves only via `requiresTrait` gates; impact moves only via a KB edit. The
scenario is driven by the *breadth* of the assumption profile, so a single/double assumption
flip is recorded but usually does not re-select the scenario.

## Storyline (bidirectional hardening)
Baseline **B0** = loosely-configured running-example container, **no assumptions** → matches
**Hybrid Cloud** (43/45 Unknown; likelihood *Possible*). From there:
- **Hardening (verify controls present):** `D1` (non-root + cap_drop, artefact) →
  recorded but no scenario/level change; `D2` (IMG/RTS/NET/AUTH/MON Satisfied) → Balanced,
  likelihood Possible→VeryUnlikely; `D3` (all Satisfied) → Production, 0 Unknown.
- **Degradation (verify controls absent):** `D4` (same five families Dissatisfied) →
  Rapid Prototype, Possible→VeryLikely; `D5` (all Dissatisfied) → High Risk, VeryLikely.
- **Structural / knowledge:** `D6` (drop `/var` mount) → ContainerDataFromLocalSystem
  risk removed (selective); `D7` (edit the Hybrid Cloud HostSystemFilesExposed node
  Moderate→Critical) → the only impact mover.

`D4` is the exact inverse of `D2` (same five families, Dissatisfied vs
Satisfied) — a clean symmetric demonstration of bidirectional re-rating.

## Why the design is shaped this way
- **Loose baseline, not a hardened one.** A near-exact scenario-profile match scores ~135 with
  45 perfect matches, so a fully-hardened baseline sits too deep in one scenario's basin for a
  single delta to move it. Hybrid Cloud (all-Unknown) is the natural starting point and is near
  enough to both Balanced (hardening) and Rapid Prototype/High Risk (degradation) for realistic
  single-variable deltas to tip it. Supplying `assumptions.conf` is therefore a *delta*, not the baseline.
- **Artefact hardening is bundled** into one `D1` step precisely to show that recorded
  posture improvements need not change the risk levels until a breadth of assumptions is set.
- **Self-documenting delta IDs** (HARDEN_*, DEGRADE_*, D6, D7) rather than opaque numbers.

## Notes for interpretation
- Only ~6 of 45 assumptions are technically verifiable from the artefacts today (NET_1, NET_2,
  RTS_1, RTS_2, RTS_3, IMG_1); the rest need `assumptions.conf`. RTS_1 (non-root) keys off the
  Compose `user:` field, NOT the Dockerfile `USER` directive.
- Some scenarios share identical ratings (Balanced≡Production, Rapid Prototype≡High Risk for these
  techniques): the factsheet still changes (scenario + assumption states) — governance/process
  assumptions refine the *context*, while the technical controls drive these *likelihoods*.
- The `.conf` parser does **not** strip inline `# comments` from values (`NET=Satisfied   # foo`
  is read literally and ignored) — keep commentary on its own `#`-lines.

## Reproduce
```
docker compose build api
bash experiment/run_all.sh        # baseline + all deltas (separate docker runs)
bash experiment/determinism.sh    # determinism check (N separate invocations)
python experiment/rollup.py       # build results/ bundle (REPORT.md, CSVs, diffs)
```
Latency for the report is captured by a short in-container timing snippet (see `results/latency.json`).
`simulate.py` reproduces scenario selection in-process for quickly exploring assumption profiles.
