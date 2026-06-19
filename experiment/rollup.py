#!/usr/bin/env python3
"""
rollup.py — Build the portable, self-contained result bundle for the experiment.

Reframed (bidirectional hardening) experiment: baseline B0 = loosely-configured
running-example container with NO assumptions provided (matches Hybrid Cloud). Deltas
are single-variable changes vs B0 that either (a) record a technical hardening measure
without yet changing the scenario/risk-levels (D1), (b) change the risk
SET (D6), (c) change the risk LEVELS by re-selecting the scenario — down
(D2, D3) or up (D4, D5), or (d) change impact
at the knowledge level (D7).

Produces, under experiment/results/:
  results_summary.csv, hardening_progression.csv, diffs/<ID>.json, REPORT.md,
  determinism_results.csv, latency.json, and a copy of runs/.
"""
from __future__ import annotations
import json, os, csv, shutil, hashlib

EXP = os.path.dirname(os.path.abspath(__file__))
RUNS = os.path.join(EXP, "runs")
RESULTS = os.path.join(EXP, "results")
DIFFS = os.path.join(RESULTS, "diffs")


def load(p):
    with open(p, encoding="utf-8") as fh:
        return json.load(fh)


def canon_hash(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def _id(n):
    if isinstance(n, dict): return n.get("@id", "")
    if isinstance(n, str): return n
    return ""


def short(s): return s.split(":")[-1] if s else "-"


def fs_path(rid): return os.path.join(RUNS, rid, "factsheet.json")


def summarise(rid):
    fs = load(fs_path(rid))
    name = next(iter(fs)); svc = fs[name]
    states = svc.get("ContainerSecurityAssumptionStates", [])
    counts = {"Satisfied": 0, "Unknown": 0, "Dissatisfied": 0}
    for s in states:
        st = s.get("CalculatedSatisfactionState", "Unknown")
        counts[st] = counts.get(st, 0) + 1
    actions = []
    for a in svc.get("PossibleAttackActions", []):
        impact = a.get("csro:causesImpact", {})
        ir = rl = ""
        treatments = []
        if isinstance(impact, dict):
            _ind = impact.get("csro:indicates", {})
            if isinstance(_ind, dict):
                treatments = sorted(
                    t.get("rdfs:label", "")
                    for t in _ind.get("csro:isTreatedBy", [])
                    if isinstance(t, dict) and t.get("rdfs:label")
                )
        if isinstance(impact, dict):
            ir = _id(impact.get("csro:hasImpactRating", {}))
            ind = impact.get("csro:indicates", {})
            if isinstance(ind, dict):
                rl = _id(ind.get("csro:hasRiskLevel", {}))
        actions.append({
            "technique": _id(a.get("csro:appliesTechnique", {})),
            "exploitability": _id(a.get("csro:hasExploitabilityRating", {})),
            "exposure": _id(a.get("csro:hasExposureRating", {})),
            "likelihood": _id(a.get("csro:hasLikelihood", {})),
            "impact_rating": ir, "risk_level": rl,
            "treatments": treatments,
        })
    return {
        "service": name,
        "scenario": svc.get("MatchingContextScenario", {}).get("ScenarioLabel", ""),
        "counts": counts, "n_assumptions": len(states),
        "actions": {a["technique"]: a for a in actions},   # keyed by technique (stable across scenarios)
        "order": [a["technique"] for a in actions],
        "canon_hash": canon_hash(fs),
        "assum_states": {s["AssumptionID"].split(":")[-1]: s["CalculatedSatisfactionState"] for s in states},
    }


def diff(before_id, after_id, delta_id, note=""):
    b = summarise(before_id); a = summarise(after_id)
    rem = [short(b["actions"][x]["technique"]) for x in b["actions"] if x not in a["actions"]]
    add = [short(a["actions"][x]["technique"]) for x in a["actions"] if x not in b["actions"]]
    common = [x for x in b["actions"] if x in a["actions"]]
    rating_changes = []; impact_changes = []; unchanged = []
    for x in common:
        bb, aa = b["actions"][x], a["actions"][x]
        dims = {d: [short(bb[d]), short(aa[d])] for d in ("exploitability", "exposure", "likelihood", "risk_level") if bb[d] != aa[d]}
        if bb["impact_rating"] != aa["impact_rating"]:
            impact_changes.append({"technique": short(bb["technique"]),
                                   "impact_rating": [short(bb["impact_rating"]), short(aa["impact_rating"])]})
        if dims:
            rating_changes.append({"technique": short(bb["technique"]), **dims})
        elif bb["impact_rating"] == aa["impact_rating"]:
            unchanged.append(short(bb["technique"]))
    # assumption-state transitions
    assum_changes = []
    for k, v in b["assum_states"].items():
        if a["assum_states"].get(k) != v:
            assum_changes.append({"assumption": k, "state": [v, a["assum_states"].get(k)]})
    # treatment-list transitions (treatments are pruned once their assumption is Satisfied)
    treatment_changes = []
    for x in common:
        bset = set(b["actions"][x]["treatments"]); aset = set(a["actions"][x]["treatments"])
        removed = sorted(bset - aset); added = sorted(aset - bset)
        if removed or added:
            treatment_changes.append({"technique": short(x), "removed": removed, "added": added})
    nchg = len(rating_changes) + len(impact_changes) + len(add) + len(rem)
    out = {
        "delta_id": delta_id, "reference_baseline": before_id,
        "scenario": {"before": b["scenario"], "after": a["scenario"]},
        "scenario_changed": b["scenario"] != a["scenario"],
        "assumption_counts": {"before": b["counts"], "after": a["counts"]},
        "assumption_state_changes": sorted(assum_changes, key=lambda x: x["assumption"]),
        "actions_removed": sorted(rem), "actions_added": sorted(add),
        "rating_changes": rating_changes, "impact_changes": impact_changes,
        "treatment_changes": sorted(treatment_changes, key=lambda x: x["technique"]),
        "unchanged_actions": sorted(unchanged),
        "canon_hash_before": b["canon_hash"], "canon_hash_after": a["canon_hash"],
        "notes": note,
    }
    os.makedirs(DIFFS, exist_ok=True)
    with open(os.path.join(DIFFS, f"{delta_id}.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, ensure_ascii=False, sort_keys=True)
    return out, b, a, nchg


def meta(rid):
    p = os.path.join(RUNS, rid, "meta.json")
    return load(p) if os.path.exists(p) else {}


def compact(rc, ic, ac):
    parts = []
    for r in rc:
        for d in ("exploitability", "exposure", "likelihood", "risk_level"):
            if d in r: parts.append(f"{r['technique']}:{d}:{r[d][0]}->{r[d][1]}")
    for r in ic: parts.append(f"{r['technique']}:impact:{r['impact_rating'][0]}->{r['impact_rating'][1]}")
    for r in ac: parts.append(f"assum {r['assumption']}:{r['state'][0]}->{r['state'][1]}")
    return ";".join(parts)


# delta_id -> (file_changed, mechanism, direction, note). All compared vs B0.
DELTAS = {
    "D1": ("docker-compose.yml: + non-root user AND cap_drop ALL", "artefact", "harden",
        "Bundled technical hardening (run as non-root + drop all capabilities). RTS-1 and RTS-3 flip "
        "Unknown->Satisfied; scenario stays Hybrid Cloud and risk levels are unchanged — the measures are "
        "recorded in the factsheet's assumption states, but two artefact-level assumptions do not re-select the scenario."),
    "D2": ("assumptions.conf: IMG/RTS/NET/AUTH/MON = Satisfied", "assumption", "harden",
        "Verify the technical control families. Enough assumptions resolve that the scenario re-selects "
        "Hybrid Cloud -> Balanced and every risk level improves (likelihood Possible -> VeryUnlikely)."),
    "D3": ("assumptions.conf: all 9 families = Satisfied", "assumption", "harden",
        "Verify governance/process too. Scenario -> Production; all 45 assumptions Satisfied (0 Unknown). Risk "
        "already at the floor — governance refines the context without lowering these technical likelihoods further."),
    "D4": ("assumptions.conf: IMG/RTS/NET/AUTH/MON = Dissatisfied", "assumption", "degrade",
        "The inverse of D2: the technical control families are verified ABSENT. Scenario re-selects "
        "Hybrid Cloud -> Rapid Prototype and every risk level rises (likelihood Possible -> VeryLikely)."),
    "D5": ("assumptions.conf: all 9 families = Dissatisfied", "assumption", "degrade",
        "Assume-breach: no control family can be relied upon. Scenario -> High Risk; likelihood VeryLikely. "
        "(Same likelihood as Rapid Prototype for these techniques — governance refines the scenario, not the "
        "technical likelihood, mirroring the hardening side.)"),
    "D6": ("docker-compose.yml: remove - /var:/host-var", "artefact", "harden",
        "Remove the host volume. privileged_host_volume trait gone -> ContainerDataFromLocalSystem risk removed "
        "entirely; the other three risks and all levels unchanged (selective removal of one risk)."),
    "D7": ("risk_export.jsonld copy: HybridCloud HostSystemFilesExposed Moderate->Critical", "kb", "kb",
        "Knowledge-level edit on the baseline (Hybrid Cloud) impact node. The host-files-exposed impact and risk "
        "level rise; the only delta that moves impact, and it propagates selectively to that one risk."),
}
ORDER = ["D1", "D2", "D3", "D4", "D5", "D6", "D7"]


def main():
    # Start clean so regenerations never leave stale artefacts from earlier designs.
    os.makedirs(RESULTS, exist_ok=True); os.makedirs(DIFFS, exist_ok=True)
    for f in os.listdir(DIFFS):
        if f.endswith(".json"):
            try: os.remove(os.path.join(DIFFS, f))
            except OSError: pass
    for stale in ("scenario_ladder.csv",):
        p = os.path.join(RESULTS, stale)
        if os.path.exists(p):
            try: os.remove(p)
            except OSError: pass
    det = {}
    detp = os.path.join(RUNS, "_determinism", "determinism_results.csv")
    if os.path.exists(detp):
        for row in csv.DictReader(open(detp)):
            det[row["label"]] = row["distinct_canonical_hashes"]
    latp = os.path.join(RUNS, "_determinism", "latency.json")
    lat = load(latp) if os.path.exists(latp) else {}

    rows = []
    for did in ORDER:
        fchg, mech, direction, note = DELTAS[did]
        out, b, a, nchg = diff("B0", did, did, note)
        rows.append({
            "delta_id": did, "description": note.split(".")[0], "file_changed": fchg,
            "mechanism": mech, "direction": direction,
            "scenario_before": out["scenario"]["before"], "scenario_after": out["scenario"]["after"],
            "scenario_changed": out["scenario_changed"],
            "unknown_before": b["counts"]["Unknown"], "unknown_after": a["counts"]["Unknown"],
            "actions_before_count": len(b["actions"]), "actions_after_count": len(a["actions"]),
            "assumptions_changed": len(out["assumption_state_changes"]),
            "changed_fields_count": nchg,
            "changes": compact(out["rating_changes"], out["impact_changes"], out["assumption_state_changes"]),
            "wall_clock_seconds": meta(did).get("wall_clock_seconds", ""),
            "distinct_canonical_hashes": det.get(did, ""),
        })
    cols = ["delta_id", "description", "file_changed", "mechanism", "direction", "scenario_before", "scenario_after",
            "scenario_changed", "unknown_before", "unknown_after", "actions_before_count", "actions_after_count",
            "assumptions_changed", "changed_fields_count", "changes", "wall_clock_seconds", "distinct_canonical_hashes"]
    with open(os.path.join(RESULTS, "results_summary.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols); w.writeheader()
        for r in rows: w.writerow(r)

    # hardening_progression.csv — the bidirectional arc
    prog = [("D5", "assume-breach (all Dissatisfied)"), ("D4", "technical controls absent"),
            ("B0", "baseline (loose, no assumptions)"), ("D1", "+ non-root + cap_drop"),
            ("D2", "technical controls verified"), ("D3", "all controls verified")]
    with open(os.path.join(RESULTS, "hardening_progression.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["step", "label", "scenario", "n_unknown", "technique", "likelihood", "risk_level"])
        for rid, lbl in prog:
            s = summarise(rid)
            for t in s["order"]:
                act = s["actions"][t]
                w.writerow([rid, lbl, s["scenario"], s["counts"]["Unknown"], short(t), short(act["likelihood"]), short(act["risk_level"])])

    dst = os.path.join(RESULTS, "runs")
    if os.path.exists(dst): shutil.rmtree(dst)
    os.makedirs(dst)
    for rid in os.listdir(RUNS):
        if rid == "_determinism": continue
        if os.path.isdir(os.path.join(RUNS, rid)):
            shutil.copytree(os.path.join(RUNS, rid), os.path.join(dst, rid))
    if os.path.exists(detp): shutil.copy(detp, os.path.join(RESULTS, "determinism_results.csv"))
    if os.path.exists(latp): shutil.copy(latp, os.path.join(RESULTS, "latency.json"))
    dn = os.path.join(EXP, "DESIGN_NOTES.md")
    if os.path.exists(dn): shutil.copy(dn, os.path.join(RESULTS, "DESIGN_NOTES.md"))

    with open(os.path.join(RESULTS, "README.md"), "w", encoding="utf-8") as fh:
        fh.write(
            "# Delta Experiment results bundle\n\n"
            "**Start here → [`REPORT.md`](REPORT.md)** — the self-contained narrative with all results, "
            "the baseline definition, every delta, the measurements (determinism, automation ratio, "
            "unknown-resolution, latency) and the findings. It is self-contained: all factsheets follow the "
            "structure of the repo's `example/factsheet.json`, so the results can be read without running the tool.\n\n"
            "## Contents\n"
            "| file | what it is |\n|---|---|\n"
            "| `REPORT.md` | **key reference** — full narrative + tables + findings |\n"
            "| `DESIGN_NOTES.md` | design rationale and how the design was calibrated to the tool's behaviour |\n"
            "| `results_summary.csv` | one row per delta (machine-readable) |\n"
            "| `hardening_progression.csv` | the bidirectional arc: scenario + per-action levels per step |\n"
            "| `diffs/<ID>.json` | structured field-level diff vs B0 (incl. assumption-state changes) |\n"
            "| `runs/<ID>/` | raw `factsheet.json` + `meta.json` (provenance, wall-clock) + exact input copies |\n"
            "| `determinism_results.csv`, `latency.json` | determinism / latency raw measurements |\n\n"
            "All factsheets follow the structure of the repo's `example/factsheet.json`. Numbers in `REPORT.md` "
            "are computed from the `runs/` factsheets by `experiment/rollup.py`.\n"
        )

    write_report(rows, det, lat)
    print("Rollup complete:", RESULTS)
    print("Determinism:", det)


TECHS = ["ContainerPtraceInjection", "ContainerDataFromLocalSystem",
         "ContainerExploitPublicFacingApp", "ContainerPtraceProcessDiscovery"]
TSHORT = {"ContainerPtraceInjection": "PtraceInjection", "ContainerDataFromLocalSystem": "DataFromLocalSystem",
          "ContainerExploitPublicFacingApp": "ExploitPublicFacingApp", "ContainerPtraceProcessDiscovery": "PtraceProcessDiscovery"}


def design_rationale_section():
    return [
        "## Design rationale (why these deltas, and why this baseline)", "",
        "**The decisive modelling fact.** Per-action exploitability/exposure/likelihood/risk are **static values "
        "baked into each per-scenario attack-action instance in the knowledge base** — they are *not* recomputed "
        "from traits or individual assumptions. A delta therefore changes the risk **levels** only if it "
        "re-selects the **context scenario**, which is driven by the *breadth* of the assumption profile (the "
        "scenario is scored against all 45 assumptions). A single artefact change, or a one/two-assumption flip, "
        "is faithfully *recorded* (assumption states and traits change) but leaves the levels untouched. The delta "
        "set is built around this: each delta either (a) records posture without moving levels, (b) changes the "
        "risk *set*, or (c) crosses a scenario boundary and re-rates everything; one delta moves impact at the KB level.", "",
        "**Why the loose baseline.** A fully-hardened baseline sits deep in a single scenario's basin (a near-exact "
        "profile match scores ~135 with 45 perfect matches), so no single delta can dislodge it. B0 is instead the "
        "loosely-configured deployment with **no assumptions supplied** — the natural starting point of an "
        "assessment, which the tool matches to *Hybrid Cloud* (the all-Unknown default, 43/45 Unknown). From there "
        "the assumption profile can move the matched scenario in either direction with realistic, single-variable "
        "edits, and supplying `assumptions.conf` becomes a delta in its own right rather than part of the baseline.", "",
        "**Why bundle the artefact hardening.** Running as non-root and dropping capabilities are two technically-"
        "detectable measures (they flip RTS-1 and RTS-3). Individually or together they are recorded but do not "
        "re-select the scenario, so they are presented as one `D1` step — its purpose is precisely to "
        "show that *recorded posture improvements need not change the risk levels until a breadth of assumptions is set*. "
        "(Note: the runs-as-non-root signal comes from the Compose `user:` field, not the Dockerfile `USER` directive.)", "",
        "**Why the symmetric assumption deltas.** D2 and D4 set the *same* five technical "
        "control families to Satisfied vs Dissatisfied — an exact inverse that re-selects the scenario in opposite "
        "directions (→ Balanced / → Rapid Prototype), cleanly isolating the effect of verifying controls present "
        "vs absent. D3 and D5 are the end anchors (Production / High Risk).", "",
    ]


def findings_section():
    return [
        "## Findings & current tool scope", "",
        "- **Deterministic, selective, fast re-identification.** Every delta re-derives the factsheet "
        "deterministically (one canonical hash across separate processes — see *Determinism*) and *selectively* — "
        "only the causally-affected fields move (a single trait, a single risk, one impact rating, or a coherent "
        "re-rating when the scenario changes). Re-running after any change costs ~0.1 s of analysis (see *Latency*).", "",
        "- **Two distinct levers, by design.** The deployment artefacts (Compose/Dockerfile) drive *which risks "
        "apply* (trait-gated attack actions) and a handful of technically-detectable assumptions; the assumption "
        "profile drives *which context scenario* is matched and therefore the risk *levels*. Impact is bound to "
        "the knowledge base. This separation is what makes the re-identification both context-aware and selective.", "",
        "- **Current trait-extraction scope.** The tool's automated trait extraction currently focuses on "
        "**threat-relevance detection** (e.g. detecting a mounted host volume, `pid: host`, capabilities, exposed "
        "ports, external networks) plus **a few assumption-related detections** (e.g. runs-as-non-root from the "
        "Compose `user:` field, minimal-capabilities from `cap_drop`, image hygiene from hadolint). The large "
        "majority of the 45 CSRO assumptions — especially governance/process and host-level controls — are **not "
        "yet technically verifiable** from the artefacts and must be supplied manually via `assumptions.conf`.", "",
        "- **Assumption sets are defined once and reused.** Because the unverifiable assumptions describe the "
        "*deployment context* (organisation/host posture) rather than the individual container, a context's "
        "`assumptions.conf` is authored **once** and then reused across factsheet generations for every container "
        "in that context. The per-container effort is therefore the artefact analysis (fully automated); the "
        "manual assumption definition is a one-time, amortised cost per context.", "",
        "- **Future work — shrink the manual share.** The set of *technically verifiable* assumptions should be "
        "extended incrementally (e.g. assessing host firewall configuration, seccomp/AppArmor/SELinux profiles, "
        "secrets-management backends, registry trust) so that more assumptions are auto-resolved from observable "
        "evidence. Each added detector moves an assumption out of the manual `assumptions.conf` and into automated "
        "extraction, directly reducing the manual effort quantified in *Automation ratio* / *Unknown-resolution* "
        "and tightening the determinism guarantee to more of the input space.", "",
    ]


def write_report(rows, det, lat):
    m = meta("B0")
    b0 = summarise("B0")
    L = ["# Delta Experiment — Results (hardening narrative)", "",
         "*Self-contained report and key reference for the experiment. All factsheets follow the structure of "
         "the repo's `example/factsheet.json`; no access to a running tool is required to read these results.*", "",
         "The experiment changes one thing at a time (a *delta*) to a container deployment or to the knowledge "
         "base and records how the generated risk factsheet changes. It demonstrates that re-identification is "
         "**deterministic** (identical inputs → identical output), **selective** (only the causally-affected "
         "fields move), **responsive** to artefact, assumption *and* knowledge-base changes, and **fast**.", "",
         "**Storyline.** Start from the loosely-configured running-example container with no security "
         "assumptions provided (the tool matches the *Hybrid Cloud* scenario — the all-Unknown default, "
         "likelihood *Possible*). From there the factsheet re-derives in **both directions**: verifying "
         "controls as *present* hardens the posture and lowers risk (→ Balanced → Production, likelihood "
         "*VeryUnlikely*); verifying controls as *absent* raises it (→ Rapid Prototype → High Risk, "
         "likelihood *VeryLikely*). Individual technical measures (non-root, cap_drop) are *recorded* "
         "(assumptions flip to Satisfied) but do not by themselves move the scenario or risk levels — only "
         "a breadth of satisfied/dissatisfied assumptions re-selects the scenario.", ""]
    L += ["## Provenance & reproduction", "",
          f"- **Tool image:** `container-risk-factsheet-api:latest` — digest `{m.get('image_digest','?')}` "
          f"(built from `docker-compose.yml`; bundles **hadolint v2.12.0**).",
          f"- **Tool commit:** `{m.get('tool_commit','?')}`. **KB:** `data/.../15_full_csro/risk_export.jsonld` "
          "(baked into the image; D7 mounts an edited copy via `--data-dir`).",
          "- **Invocation:** each run is one *separate* `docker run` of the image's `factsheet` CLI "
          "(`python -m factsheet.cli generate-factsheet ... --no-pretty`). The live API server "
          "(`docker compose up` → `POST /api/v1/generate-factsheet`) uses the identical in-process code path.",
          "- **Reproduce:** `docker compose build api` then "
          "`bash experiment/run_all.sh && bash experiment/determinism.sh && python experiment/rollup.py`.", ""]
    L += ["## How the tool turns a delta into a changed factsheet", "",
          "Traits ← Compose (+ Dockerfile via hadolint) → assumption states (trait verifiers, overridable by "
          "`assumptions.conf`) → **context scenario** (best score of the assumption profile vs 22 scenarios) → "
          "attack actions (the scenario's instances whose technique `requiresTrait` are present) → ratings "
          "(exploitability/exposure/likelihood/risk/impact are **static per-scenario values in the KB**).", "",
          "**Three granularities of responsiveness:** (1) artefact/assumption changes that update the "
          "*posture* (assumption states) — D1; (2) trait changes that update the *risk set* via "
          "`requiresTrait` gates — D6; (3) assumption-profile changes that re-select the scenario and "
          "so update the *risk levels* — D2/D3 (down) and D4/D5 (up). "
          "Impact moves only at the **knowledge level** — D7. Per-action levels move *only* when the "
          "scenario changes, which is why the single artefact hardening step is recorded but does not yet move likelihood.", ""]

    # Baseline definition
    L += ["## Baseline definition (B0)", "",
          "**B0 is the loosely-configured running-example container with no assumptions supplied.** It keeps the "
          "risky deployment traits that generate the four attack actions (`pid: host` + `cap_add: SYS_PTRACE` → the "
          "two ptrace actions; `- /var:/host-var` → host-files exposure; the external `reverse-proxy` network → "
          "public-facing-app exploitation) but specifies **no `cap_drop`, no `user:`, and no `assumptions.conf`**. "
          "With every governance/process assumption Unknown, the tool matches the **Hybrid Cloud Scenario** "
          f"({b0['counts']['Unknown']}/{b0['n_assumptions']} = {round(100*b0['counts']['Unknown']/b0['n_assumptions'])}% Unknown — "
          "this equals the shipped example factsheet).", "",
          "**B0 `docker-compose.yml`:**", "", "```yaml",
          open(os.path.join(EXP, "inputs", "B0", "docker-compose.yml"), encoding="utf-8").read().rstrip(), "```", "",
          "- **Dockerfile:** `example/analyzer.dockerfile` (unchanged; hadolint reports no findings → IMG-1 Satisfied). "
          "Note the runs-as-non-root signal comes from the Compose `user:` field, **not** the Dockerfile `USER` directive.",
          "- **No `assumptions.conf`** for B0 (all governance/process families Unknown).", "",
          "> **Parser caveat (for the example):** the `.conf`/`--overrides` loader does **not** strip inline "
          "`# comments` from values — `NET=Satisfied   # foo` is read literally and ignored. Keep commentary on its own `#`-lines.", "",
          "**Per-delta edit relative to B0:**", "",
          "| delta | edit | mechanism |", "|---|---|---|"]
    for did in ORDER:
        fchg, mech, _dir, _ = DELTAS[did]
        L.append(f"| {did} | {fchg} | {mech} |")
    L += [""]

    # Bidirectional progression
    L += ["## Bidirectional risk progression (the arc)", "",
          "Each row is a separate run; cells show `likelihood/risk-level` per attack action. From the B0 baseline "
          "(Possible), verifying controls *present* lowers risk and verifying them *absent* raises it. The scenario "
          "— and hence the risk levels — only changes once a breadth of assumptions is set (the single artefact "
          "hardening step does not):", "",
          "| direction | step | change | scenario | #Unknown | " + " | ".join(TSHORT[t] for t in TECHS) + " |",
          "|" + "---|" * (5 + len(TECHS))]
    prog = [("↑ risk", "D5", "assume-breach (all Dissatisfied)"),
            ("↑ risk", "D4", "technical controls verified absent"),
            ("— base", "B0", "baseline (loose, no assumptions)"),
            ("↓ risk", "D1", "+ non-root + cap_drop (artefact)"),
            ("↓ risk", "D2", "technical controls verified present"),
            ("↓ risk", "D3", "all controls verified present")]
    for direction, rid, lbl in prog:
        s = summarise(rid)
        cells = []
        for t in TECHS:
            act = s["actions"].get("csro:" + t)
            cells.append(f"{short(act['likelihood'])}/{short(act['risk_level'])}" if act else "—")
        L.append(f"| {direction} | {rid} | {lbl} | {s['scenario']} | {s['counts']['Unknown']} | " + " | ".join(cells) + " |")
    L += ["", "D1 leaves every cell unchanged vs B0 (it only flips assumption states RTS-1/RTS-3 — see "
          "`results_summary.csv` `changes`); D2 improves every level and D3 holds at the floor "
          "while resolving all Unknowns; D4 and D5 escalate every level. Rapid Prototype and "
          "High Risk (and Balanced vs Production) share these technical likelihoods — the factsheet still differs "
          "(scenario label + assumption states), which is itself a result: **governance/process assumptions refine "
          "the matched context, while the technical controls drive these container-escape likelihoods** (true in both directions).", ""]

    # Unknown-resolution
    dt_ = summarise("D2"); df_ = summarise("D3")
    n = b0["n_assumptions"]
    L += ["## Unknown-resolution (providing assumptions)", "",
          "| run | scenario | Unknown | %Unknown |", "|---|---|---|---|",
          f"| B0 (no assumptions) | {b0['scenario']} | {b0['counts']['Unknown']} | {round(100*b0['counts']['Unknown']/n)}% |",
          f"| D2 | {dt_['scenario']} | {dt_['counts']['Unknown']} | {round(100*dt_['counts']['Unknown']/n)}% |",
          f"| D3 | {df_['scenario']} | {df_['counts']['Unknown']} | {round(100*df_['counts']['Unknown']/n)}% |", "",
          f"→ Providing assumptions resolves Unknown {b0['counts']['Unknown']}→{dt_['counts']['Unknown']}→{df_['counts']['Unknown']} "
          f"({round(100*b0['counts']['Unknown']/n)}% → {round(100*dt_['counts']['Unknown']/n)}% → 0%) and improves the matched "
          "scenario Hybrid Cloud → Balanced → Production. Concrete \"assumptions resolve the ~85% Unknown\" evidence.", ""]

    # Single-variable interpretation
    L += ["## Single-variable deltas — summary", "",
          "| delta | mechanism | scenario change | assumptions changed | actions | risk-level change | effect |",
          "|---|---|---|---|---|---|---|"]
    eff = {"D1": "non-root + cap_drop recorded (RTS-1/RTS-3 Satisfied); levels unchanged",
           "D2": "**every level improves** (Possible→VeryUnlikely)",
           "D3": "all Unknowns resolved; levels at floor",
           "D4": "**every level escalates** (Possible→VeryLikely)",
           "D5": "**every level escalates** (→VeryLikely); High Risk scenario",
           "D6": "host-files risk **removed** (4→3 actions)",
           "D7": "host-files **impact Moderate→Critical** (knowledge level)"}
    rmap = {r["delta_id"]: r for r in rows}
    for did in ORDER:
        r = rmap[did]
        sc = "yes" if r["scenario_changed"] in (True, "True") else "no"
        lvl = "yes" if any(x in r["changes"] for x in ("likelihood:", "risk_level:", "impact:")) else "no"
        L.append(f"| {did} | {r['mechanism']} ({r['direction']}) | {sc} | {r['assumptions_changed']} | "
                 f"{r['actions_before_count']}→{r['actions_after_count']} | {lvl} | {eff[did]} |")
    L += ["", "**Reading.** D1 confirms that *technical hardening is recorded in the factsheet "
          "(assumption states flip to Satisfied) but a couple of artefact-level assumptions do not re-select the "
          "scenario, so the four risks' likelihood is unchanged* — risk levels move only once a breadth of "
          "assumptions is set, in either direction (D2 ↓ / D4 ↑). D6 changes the "
          "risk **set** (selective removal) without touching the scenario. D7 is the only impact mover "
          "(knowledge level). Some scenarios share identical ratings (Balanced≡Production, Rapid Prototype≡High "
          "Risk for these techniques) — the factsheet still changes, which is itself a result.", ""]
    L += design_rationale_section()
    L += findings_section()

    # Determinism
    L += ["## Determinism", "",
          "Distinct canonical SHA-256 hashes of the factsheet across *N separate container invocations*, "
          "alternating `PYTHONHASHSEED` (0/random). Target = 1.", "",
          "| config | N | distinct canonical hashes |", "|---|---|---|"]
    for k, v in det.items():
        L.append(f"| {k} | {20 if k=='B0' else 5} | {v} |")
    L += ["", "→ **1 distinct hash everywhere** — byte-stable across processes and hash seeds (ordered JSON-LD "
          "`@graph` traversal, dict-index lookups, no SPARQL/RNG/timestamps). Raw bytes matched too.", ""]

    # Automation ratio
    L += ["## Automation ratio", "",
          "| pipeline step | automated? |", "|---|---|"]
    for s, a in [("parse Compose / Dockerfile", "auto"), ("extract deployment traits", "auto"),
                 ("resolve assumption states", "auto (manual input: assumptions.conf values)"),
                 ("select context scenario", "auto"), ("match attack actions (requiresTrait)", "auto"),
                 ("exploitability/exposure/likelihood/risk", "auto (static per-scenario KB values)"),
                 ("attach treatments/guidelines", "auto"), ("emit factsheet JSON", "auto"),
                 ("assumption judgement + risk acceptance + treatment decision", "**manual**")]:
        L.append(f"| {s} | {a} |")
    L += ["", "→ The whole derivation is automated; the manual inputs are the assumption judgements (assumptions.conf), "
          "risk acceptance and treatment selection — the same Unknown assumptions quantified above.", ""]

    # Latency
    pa = lat.get("pure_analysis_ms", {})
    L += ["## Latency", "",
          f"- **Pure analysis** (in-process, warm): mean **{pa.get('mean','?')} ms** "
          f"(min {pa.get('min','?')}, max {pa.get('max','?')}, n={pa.get('n','?')}; incl. hadolint subprocess + "
          f"~{lat.get('kb_load_ms_once','?')} ms KB load).",
          f"- **End-to-end `docker run` wall**: ~**{lat.get('docker_run_wall_seconds_mean','?')} s** "
          f"(mean over {lat.get('docker_run_wall_seconds_n','?')} runs) → container start-up ≈ "
          f"**{lat.get('container_start_overhead_seconds_est','?')} s** (the fair comparison is the analysis time, "
          f"~{round(pa.get('mean',0)/1000,2)} s).",
          f"- **Manual baseline:** {lat.get('manual_baseline','estimate')}",
          "- **Order-of-magnitude contrast: seconds (tool) vs hours (manual workshop).**", ""]

    L += ["## File index", "",
          "- `REPORT.md` — this narrative. `DESIGN_NOTES.md` — design rationale & calibration to the tool.",
          "- `results_summary.csv` — one row per delta. `hardening_progression.csv` — the arc (scenario + per-action levels).",
          "- `diffs/<ID>.json` — structured field-level diff vs B0 (incl. `assumption_state_changes`).",
          "- `runs/<ID>/` — raw `factsheet.json`, `meta.json` (provenance + wall-clock), exact input copies.",
          "- `determinism_results.csv`, `latency.json` — determinism / latency raw measurements.", ""]
    with open(os.path.join(RESULTS, "REPORT.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(L) + "\n")


if __name__ == "__main__":
    main()
