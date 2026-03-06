# How Factsheet Generation Works

This page explains the internal pipeline that turns a Docker Compose file into a security risk factsheet.

---

## The pipeline

```
Docker Compose file
       │
       ▼
 [1] Compose Normalizer        → canonical service dict
       │
       ▼
 [2] Trait Extractor           → list of DeploymentTraits per service
       │
  (+ Dockerfile Analyzer)      → optional extra traits from Hadolint
       │
       ▼
 [3] Risk Model loader         → CSRO knowledge graph (JSON-LD)
       │
       ▼
 [4] Assumption Evaluator      → ContainerSecurityAssumptionStates
       │
       ▼
 [5] Scenario Matcher          → MatchingContextScenario
       │
       ▼
 [6] Attack Action Filter      → PossibleAttackActions
       │
       ▼
 JSON factsheet (per service)
```

---

## Stage 1 — Compose Normalizer

Docker Compose supports multiple syntaxes for the same concept (e.g. `ports: "8080:80"` vs `ports: [{target: 80, published: 8080}]`).  The normalizer canonicalises all these forms so downstream stages always see structured dicts.

Source: `factsheet/compose_normalizer.py`

---

## Stage 2 — Trait Extractor

A trait is a boolean security property that is either present or absent for a service.  The extractor scans the normalised Compose dict and emits traits like:

- `publicly_exposed` — any host port binding exists
- `privileged_flag` — `privileged: true`
- `host_pid` — `pid: host`
- `read_only_filesystem` — `read_only: true`
- `no_new_privileges` — `security_opt` includes `no-new-privileges:true`
- `secret_mounted` — a Docker secret is mounted

If Hadolint is available and Dockerfiles are supplied, additional traits are appended from static Dockerfile analysis (see the [Dockerfile analysis how-to](../how-to-guides/analyse-dockerfiles.md)).

Source: `factsheet/trait_extractor.py`, `factsheet/dockerfile_analyzer.py`

---

## Stage 3 — Risk Model loader

The CSRO (Container Security Risk Ontology) knowledge graph is stored as JSON-LD files in `data/tra_model/`.  The loader parses these files and exposes:

- **Security assumptions** — 45 assertions about a container's security posture (e.g. *"The container does not run as root"*)
- **Context scenarios** — deployment archetypes (e.g. *Hybrid Cloud*, *On-Premise Private Network*)
- **Attack actions** — threats that can materialise given a particular scenario and trait set

Source: `factsheet/risk_model.py`

---

## Stage 4 — Assumption Evaluator

Each assumption has a verification criterion:

- **`isVerifiableBy`** — a trait must be *present* for the assumption to be `Satisfied`
- **`isVerifiableByAbsence`** — a trait must be *absent* for the assumption to be `Satisfied`

If the criterion is not met (trait absent/present when it shouldn't be), the state is `Unknown`.  Manual overrides (see [override how-to](../how-to-guides/override-assumptions.md)) take precedence over inferred states.

Source: `factsheet/assumption_evaluator.py`

---

## Stage 5 — Scenario Matcher

Each context scenario has a set of required traits and required assumption states.  The matcher scores all scenarios against the current service profile and selects the best fit, breaking ties by score.

Source: `factsheet/scenario_matcher.py`

---

## Stage 6 — Attack Action Filter

The matched scenario carries a set of applicable attack actions from the CSRO graph.  For each action the evaluator checks preconditions (required traits and/or assumption states) and includes it in `PossibleAttackActions` if the preconditions are met.

---

## Treatment Report

After generating a factsheet, the treatment report extractor walks the nested structure:

```
PossibleAttackAction
  └─ csro:causesImpact
       └─ csro:indicates  (Risk node with csro:hasRiskLevel)
            └─ csro:isTreatedBy[]  (RiskTreatment nodes)
```

Treatments are:
- **Deduplicated** by `@id` within each service
- **Grouped** by risk level: Critical → High → Moderate → Low → Unknown

Source: `factsheet/treatment_report.py`

---

## Data files

| File | Content |
|------|---------|
| `data/tra_model/query_results/15_full_csro/risk_export.jsonld` | CSRO knowledge graph (scenarios, assumptions, attack actions, treatments) |
| `data/tra_model/query_results/15_full_csro/rule_export.jsonld` | Scoring rules and weights |
| `data/schemas/` | JSON schemas for validation |
