# Delta Experiment — Results (hardening narrative)

*Self-contained report and key reference for the experiment. All factsheets follow the structure of the repo's `example/factsheet.json`; no access to a running tool is required to read these results.*

The experiment changes one thing at a time (a *delta*) to a container deployment or to the knowledge base and records how the generated risk factsheet changes. It demonstrates that re-identification is **deterministic** (identical inputs → identical output), **selective** (only the causally-affected fields move), **responsive** to artefact, assumption *and* knowledge-base changes, and **fast**.

**Storyline.** Start from the loosely-configured running-example container with no security assumptions provided (the tool matches the *Hybrid Cloud* scenario — the all-Unknown default, likelihood *Possible*). From there the factsheet re-derives in **both directions**: verifying controls as *present* hardens the posture and lowers risk (→ Balanced → Production, likelihood *VeryUnlikely*); verifying controls as *absent* raises it (→ Rapid Prototype → High Risk, likelihood *VeryLikely*). Individual technical measures (non-root, cap_drop) are *recorded* (assumptions flip to Satisfied) but do not by themselves move the scenario or risk levels — only a breadth of satisfied/dissatisfied assumptions re-selects the scenario.

## Provenance & reproduction

- **Tool image:** `container-risk-factsheet-api:latest` — digest `sha256:a041e5e7479be1d780fd3173de21aa9f65befdf80839706f2c40d2fc72af5896` (built from `docker-compose.yml`; bundles **hadolint v2.12.0**).
- **Tool commit:** `8b684ee`. **KB:** `data/.../15_full_csro/risk_export.jsonld` (baked into the image; KB_IMPACT mounts an edited copy via `--data-dir`).
- **Invocation:** each run is one *separate* `docker run` of the image's `factsheet` CLI (`python -m factsheet.cli generate-factsheet ... --no-pretty`). The live API server (`docker compose up` → `POST /api/v1/generate-factsheet`) uses the identical in-process code path.
- **Reproduce:** `docker compose build api` then `bash experiment/run_all.sh && bash experiment/determinism.sh && python experiment/rollup.py`.

## How the tool turns a delta into a changed factsheet

Traits ← Compose (+ Dockerfile via hadolint) → assumption states (trait verifiers, overridable by `assumptions.conf`) → **context scenario** (best score of the assumption profile vs 22 scenarios) → attack actions (the scenario's instances whose technique `requiresTrait` are present) → ratings (exploitability/exposure/likelihood/risk/impact are **static per-scenario values in the KB**).

**Three granularities of responsiveness:** (1) artefact/assumption changes that update the *posture* (assumption states) — HARDEN_ARTEFACT; (2) trait changes that update the *risk set* via `requiresTrait` gates — REMOVE_VOLUME; (3) assumption-profile changes that re-select the scenario and so update the *risk levels* — HARDEN_TECH/HARDEN_FULL (down) and DEGRADE_TECH/DEGRADE_BREACH (up). Impact moves only at the **knowledge level** — KB_IMPACT. Per-action levels move *only* when the scenario changes, which is why the single artefact hardening step is recorded but does not yet move likelihood.

## Baseline definition (B0)

**B0 is the loosely-configured running-example container with no assumptions supplied.** It keeps the risky deployment traits that generate the four attack actions (`pid: host` + `cap_add: SYS_PTRACE` → the two ptrace actions; `- /var:/host-var` → host-files exposure; the external `reverse-proxy` network → public-facing-app exploitation) but specifies **no `cap_drop`, no `user:`, and no `assumptions.conf`**. With every governance/process assumption Unknown, the tool matches the **Hybrid Cloud Scenario** (43/45 = 96% Unknown — this equals the shipped example factsheet).

**B0 `docker-compose.yml`:**

```yaml
version: '3.8'

services:
  analyzer:
    image: analyzer:latest # Use the latest analyzer image
    ports:
      - "3000:3000"        # Map host port 3000 to container port 3000
    pid: "host"            # Use host PID namespace
    cap_add:
      - SYS_PTRACE         # Add capability for ptrace
    networks:
      - reverse-proxy      # Connect to external reverse-proxy network
    volumes:
      - /var:/host-var     # Mount host /var directory
        
networks:
  reverse-proxy:
    external: true         # Use an external network named 'reverse-proxy'
```

- **Dockerfile:** `example/analyzer.dockerfile` (unchanged; hadolint reports no findings → IMG-1 Satisfied). Note the runs-as-non-root signal comes from the Compose `user:` field, **not** the Dockerfile `USER` directive.
- **No `assumptions.conf`** for B0 (all governance/process families Unknown).

> **Parser caveat (for the example):** the `.conf`/`--overrides` loader does **not** strip inline `# comments` from values — `NET=Satisfied   # foo` is read literally and ignored. Keep commentary on its own `#`-lines.

**Per-delta edit relative to B0:**

| delta | edit | mechanism |
|---|---|---|
| HARDEN_ARTEFACT | docker-compose.yml: + non-root user AND cap_drop ALL | artefact |
| HARDEN_TECH | assumptions.conf: IMG/RTS/NET/AUTH/MON = Satisfied | assumption |
| HARDEN_FULL | assumptions.conf: all 9 families = Satisfied | assumption |
| DEGRADE_TECH | assumptions.conf: IMG/RTS/NET/AUTH/MON = Dissatisfied | assumption |
| DEGRADE_BREACH | assumptions.conf: all 9 families = Dissatisfied | assumption |
| REMOVE_VOLUME | docker-compose.yml: remove - /var:/host-var | artefact |
| KB_IMPACT | risk_export.jsonld copy: HybridCloud HostSystemFilesExposed Moderate->Critical | kb |

## Bidirectional risk progression (the arc)

Each row is a separate run; cells show `likelihood/risk-level` per attack action. From the B0 baseline (Possible), verifying controls *present* lowers risk and verifying them *absent* raises it. The scenario — and hence the risk levels — only changes once a breadth of assumptions is set (the single artefact hardening step does not):

| direction | step | change | scenario | #Unknown | PtraceInjection | DataFromLocalSystem | ExploitPublicFacingApp | PtraceProcessDiscovery |
|---|---|---|---|---|---|---|---|---|
| ↑ risk | DEGRADE_BREACH | assume-breach (all Dissatisfied) | High Risk Scenario | 0 | VeryLikely/Major | VeryLikely/Significant | VeryLikely/Major | Possible/Moderate |
| ↑ risk | DEGRADE_TECH | technical controls verified absent | Rapid Prototype Scenario | 17 | VeryLikely/Major | VeryLikely/Significant | VeryLikely/Major | Possible/Moderate |
| — base | B0 | baseline (loose, no assumptions) | Hybrid Cloud Scenario | 43 | Possible/Significant | Possible/Moderate | Unlikely/Moderate | Unlikely/Moderate |
| ↓ risk | HARDEN_ARTEFACT | + non-root + cap_drop (artefact) | Hybrid Cloud Scenario | 41 | Possible/Significant | Possible/Moderate | Unlikely/Moderate | Unlikely/Moderate |
| ↓ risk | HARDEN_TECH | technical controls verified present | Balanced Container Security Scenario | 17 | VeryUnlikely/Moderate | VeryUnlikely/Minor | VeryUnlikely/Minor | VeryUnlikely/Minor |
| ↓ risk | HARDEN_FULL | all controls verified present | Production Scenario | 0 | VeryUnlikely/Moderate | VeryUnlikely/Minor | VeryUnlikely/Minor | VeryUnlikely/Minor |

HARDEN_ARTEFACT leaves every cell unchanged vs B0 (it only flips assumption states RTS-1/RTS-3 — see `results_summary.csv` `changes`); HARDEN_TECH improves every level and HARDEN_FULL holds at the floor while resolving all Unknowns; DEGRADE_TECH and DEGRADE_BREACH escalate every level. Rapid Prototype and High Risk (and Balanced vs Production) share these technical likelihoods — the factsheet still differs (scenario label + assumption states), which is itself a result: **governance/process assumptions refine the matched context, while the technical controls drive these container-escape likelihoods** (true in both directions).

## Unknown-resolution (providing assumptions)

| run | scenario | Unknown | %Unknown |
|---|---|---|---|
| B0 (no assumptions) | Hybrid Cloud Scenario | 43 | 96% |
| HARDEN_TECH | Balanced Container Security Scenario | 17 | 38% |
| HARDEN_FULL | Production Scenario | 0 | 0% |

→ Providing assumptions resolves Unknown 43→17→0 (96% → 38% → 0%) and improves the matched scenario Hybrid Cloud → Balanced → Production. Concrete "assumptions resolve the ~85% Unknown" evidence.

## Single-variable deltas — summary

| delta | mechanism | scenario change | assumptions changed | actions | risk-level change | effect |
|---|---|---|---|---|---|---|
| HARDEN_ARTEFACT | artefact (harden) | no | 2 | 4→4 | no | non-root + cap_drop recorded (RTS-1/RTS-3 Satisfied); levels unchanged |
| HARDEN_TECH | assumption (harden) | yes | 27 | 4→4 | yes | **every level improves** (Possible→VeryUnlikely) |
| HARDEN_FULL | assumption (harden) | yes | 44 | 4→4 | yes | all Unknowns resolved; levels at floor |
| DEGRADE_TECH | assumption (degrade) | yes | 27 | 4→4 | yes | **every level escalates** (Possible→VeryLikely) |
| DEGRADE_BREACH | assumption (degrade) | yes | 44 | 4→4 | yes | **every level escalates** (→VeryLikely); High Risk scenario |
| REMOVE_VOLUME | artefact (harden) | no | 0 | 4→3 | no | host-files risk **removed** (4→3 actions) |
| KB_IMPACT | kb (kb) | no | 0 | 4→4 | yes | host-files **impact Moderate→Critical** (knowledge level) |

**Reading.** HARDEN_ARTEFACT confirms that *technical hardening is recorded in the factsheet (assumption states flip to Satisfied) but a couple of artefact-level assumptions do not re-select the scenario, so the four risks' likelihood is unchanged* — risk levels move only once a breadth of assumptions is set, in either direction (HARDEN_TECH ↓ / DEGRADE_TECH ↑). REMOVE_VOLUME changes the risk **set** (selective removal) without touching the scenario. KB_IMPACT is the only impact mover (knowledge level). Some scenarios share identical ratings (Balanced≡Production, Rapid Prototype≡High Risk for these techniques) — the factsheet still changes, which is itself a result.

## Design rationale (why these deltas, and why this baseline)

**The decisive modelling fact.** Per-action exploitability/exposure/likelihood/risk are **static values baked into each per-scenario attack-action instance in the knowledge base** — they are *not* recomputed from traits or individual assumptions. A delta therefore changes the risk **levels** only if it re-selects the **context scenario**, which is driven by the *breadth* of the assumption profile (the scenario is scored against all 45 assumptions). A single artefact change, or a one/two-assumption flip, is faithfully *recorded* (assumption states and traits change) but leaves the levels untouched. The delta set is built around this: each delta either (a) records posture without moving levels, (b) changes the risk *set*, or (c) crosses a scenario boundary and re-rates everything; one delta moves impact at the KB level.

**Why the loose baseline.** A fully-hardened baseline sits deep in a single scenario's basin (a near-exact profile match scores ~135 with 45 perfect matches), so no single delta can dislodge it. B0 is instead the loosely-configured deployment with **no assumptions supplied** — the natural starting point of an assessment, which the tool matches to *Hybrid Cloud* (the all-Unknown default, 43/45 Unknown). From there the assumption profile can move the matched scenario in either direction with realistic, single-variable edits, and supplying `assumptions.conf` becomes a delta in its own right rather than part of the baseline.

**Why bundle the artefact hardening.** Running as non-root and dropping capabilities are two technically-detectable measures (they flip RTS-1 and RTS-3). Individually or together they are recorded but do not re-select the scenario, so they are presented as one `HARDEN_ARTEFACT` step — its purpose is precisely to show that *recorded posture improvements need not change the risk levels until a breadth of assumptions is set*. (Note: the runs-as-non-root signal comes from the Compose `user:` field, not the Dockerfile `USER` directive.)

**Why the symmetric assumption deltas.** HARDEN_TECH and DEGRADE_TECH set the *same* five technical control families to Satisfied vs Dissatisfied — an exact inverse that re-selects the scenario in opposite directions (→ Balanced / → Rapid Prototype), cleanly isolating the effect of verifying controls present vs absent. HARDEN_FULL and DEGRADE_BREACH are the end anchors (Production / High Risk).

## Findings & current tool scope

- **Deterministic, selective, fast re-identification.** Every delta re-derives the factsheet deterministically (one canonical hash across separate processes — see *Determinism*) and *selectively* — only the causally-affected fields move (a single trait, a single risk, one impact rating, or a coherent re-rating when the scenario changes). Re-running after any change costs ~0.1 s of analysis (see *Latency*).

- **Two distinct levers, by design.** The deployment artefacts (Compose/Dockerfile) drive *which risks apply* (trait-gated attack actions) and a handful of technically-detectable assumptions; the assumption profile drives *which context scenario* is matched and therefore the risk *levels*. Impact is bound to the knowledge base. This separation is what makes the re-identification both context-aware and selective.

- **Current trait-extraction scope.** The tool's automated trait extraction currently focuses on **threat-relevance detection** (e.g. detecting a mounted host volume, `pid: host`, capabilities, exposed ports, external networks) plus **a few assumption-related detections** (e.g. runs-as-non-root from the Compose `user:` field, minimal-capabilities from `cap_drop`, image hygiene from hadolint). The large majority of the 45 CSRO assumptions — especially governance/process and host-level controls — are **not yet technically verifiable** from the artefacts and must be supplied manually via `assumptions.conf`.

- **Assumption sets are defined once and reused.** Because the unverifiable assumptions describe the *deployment context* (organisation/host posture) rather than the individual container, a context's `assumptions.conf` is authored **once** and then reused across factsheet generations for every container in that context. The per-container effort is therefore the artefact analysis (fully automated); the manual assumption definition is a one-time, amortised cost per context.

- **Future work — shrink the manual share.** The set of *technically verifiable* assumptions should be extended incrementally (e.g. assessing host firewall configuration, seccomp/AppArmor/SELinux profiles, secrets-management backends, registry trust) so that more assumptions are auto-resolved from observable evidence. Each added detector moves an assumption out of the manual `assumptions.conf` and into automated extraction, directly reducing the manual effort quantified in *Automation ratio* / *Unknown-resolution* and tightening the determinism guarantee to more of the input space.

## Determinism

Distinct canonical SHA-256 hashes of the factsheet across *N separate container invocations*, alternating `PYTHONHASHSEED` (0/random). Target = 1.

| config | N | distinct canonical hashes |
|---|---|---|
| B0 | 20 | 1 |
| HARDEN_TECH | 5 | 1 |
| HARDEN_FULL | 5 | 1 |
| DEGRADE_TECH | 5 | 1 |
| DEGRADE_BREACH | 5 | 1 |
| KB_IMPACT | 5 | 1 |

→ **1 distinct hash everywhere** — byte-stable across processes and hash seeds (ordered JSON-LD `@graph` traversal, dict-index lookups, no SPARQL/RNG/timestamps). Raw bytes matched too.

## Automation ratio

| pipeline step | automated? |
|---|---|
| parse Compose / Dockerfile | auto |
| extract deployment traits | auto |
| resolve assumption states | auto (manual input: assumptions.conf values) |
| select context scenario | auto |
| match attack actions (requiresTrait) | auto |
| exploitability/exposure/likelihood/risk | auto (static per-scenario KB values) |
| attach treatments/guidelines | auto |
| emit factsheet JSON | auto |
| assumption judgement + risk acceptance + treatment decision | **manual** |

→ The whole derivation is automated; the manual inputs are the assumption judgements (assumptions.conf), risk acceptance and treatment selection — the same Unknown assumptions quantified above.

## Latency

- **Pure analysis** (in-process, warm): mean **104.4 ms** (min 100.5, max 108.0, n=20; incl. hadolint subprocess + ~14.4 ms KB load).
- **End-to-end `docker run` wall**: ~**2.0 s** (mean over 8 runs) → container start-up ≈ **1.9 s** (the fair comparison is the analysis time, ~0.1 s).
- **Manual baseline:** no measured duration; interview-grounded estimate of >=1 expert workshop (~3-4h), often several iterations. Order-of-magnitude contrast: seconds (tool) vs hours (manual). Labelled estimate, not a controlled measurement.
- **Order-of-magnitude contrast: seconds (tool) vs hours (manual workshop).**

## File index

- `REPORT.md` — this narrative. `DESIGN_NOTES.md` — design rationale & calibration to the tool.
- `results_summary.csv` — one row per delta. `hardening_progression.csv` — the arc (scenario + per-action levels).
- `diffs/<ID>.json` — structured field-level diff vs B0 (incl. `assumption_state_changes`).
- `runs/<ID>/` — raw `factsheet.json`, `meta.json` (provenance + wall-clock), exact input copies.
- `determinism_results.csv`, `latency.json` — determinism / latency raw measurements.

