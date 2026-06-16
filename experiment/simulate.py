#!/usr/bin/env python3
"""
simulate.py — Fast in-process scenario-selection simulator for designing deltas.

Reproduces the tool's scenario choice + per-action likelihood for an arbitrary
assumptions override profile, WITHOUT a Docker run, so we can search for a base
profile (B0) that sits near a boundary such that a delta tips the matched scenario.
"""
from __future__ import annotations
import sys, yaml, json
from factsheet.compose_normalizer import normalize_compose
from factsheet.trait_extractor import extract_all_traits
from factsheet.dockerfile_analyzer import hadolint_findings_to_traits
from factsheet.risk_model import load_risk_model, find_by_id, get_ref, get_ref_array, extract_trait_names
from factsheet.scenario_matcher import find_best_scenario, _get_original_state, _score_scenario
from factsheet.assumption_evaluator import calculate_satisfaction_with_overrides, _get_ref_array

DATA = "data"
COMPOSE = "example/docker-compose.yml"

def base_traits(no_cap_drop=False, user=None):
    compose = yaml.safe_load(open(COMPOSE, encoding="utf-8"))
    if no_cap_drop:
        compose["services"]["analyzer"].pop("cap_drop", None)
    if user is not None:
        compose["services"]["analyzer"]["user"] = user
    norm = normalize_compose(compose)
    traits = extract_all_traits(norm)["analyzer"]
    # emulate hadolint clean result (image bundles hadolint; example DF is clean)
    traits += hadolint_findings_to_traits([], "analyzer")
    return [t["id"] for t in traits]

MODEL = load_risk_model(DATA)

def select(overrides, traits=None):
    traits = traits if traits is not None else base_traits()
    sid = find_best_scenario(MODEL, traits, overrides)
    return sid.split(":")[-1]

def actions(overrides, traits=None):
    """Return {technique: (exploitability, exposure, likelihood, risk_level)} for the matched scenario."""
    traits = traits if traits is not None else base_traits()
    sid = find_best_scenario(MODEL, traits, overrides)
    trait_set = {t.lower() for t in traits}
    out = {}
    for action in MODEL.attack_actions:
        if get_ref(action, "csro:inContext") != sid:
            continue
        tech_ref = get_ref(action, "csro:appliesTechnique")
        tnode = find_by_id(tech_ref, MODEL) if tech_ref else None
        if tnode is None:
            continue
        req = extract_trait_names(get_ref_array(tnode, "csro:requiresTrait"))
        if not all(r.lower() in trait_set for r in req):
            continue
        def rid(p):
            v = action.get(p);
            return (v.get("@id") if isinstance(v, dict) else v or "").split(":")[-1]
        impact = action.get("csro:causesImpact", {})
        ir = rl = ""
        if isinstance(impact, dict):
            iref = get_ref(impact, "csro:hasImpactRating"); ir = iref.split(":")[-1]
            indr = get_ref(impact, "csro:indicates"); ind = find_by_id(indr, MODEL) if indr else None
            if ind: rl = get_ref(ind, "csro:hasRiskLevel").split(":")[-1]
        out[tech_ref.split(":")[-1]] = (rid("csro:hasExploitabilityRating"), rid("csro:hasExposureRating"),
                                        rid("csro:hasLikelihood"), rl, ir)
    return sid.split(":")[-1], out

def scenario_profile(sid_short):
    sc = find_by_id(f"csro:{sid_short}", MODEL)
    prof = {}
    for aref in _get_ref_array(sc, "csro:includesAssumption"):
        ais = find_by_id(aref, MODEL)
        if not ais: continue
        fa = get_ref(ais, "csro:forAssumption")
        if not fa: continue
        prof[fa.split(":")[-1].replace("_","-")] = _get_original_state(ais)
    return prof

def conf_from_profile(sid_short):
    return scenario_profile(sid_short)

D3_FLIP = {"NET": "Dissatisfied", "RTS-4": "Dissatisfied", "RTS-5": "Dissatisfied",
           "RTS-6": "Dissatisfied", "RTS-7": "Dissatisfied"}

def lik(d):  # compact likelihood string across the 4 techniques
    return ", ".join(f"{k.replace('Container','')[:14]}={v[2]}" for k,v in sorted(d.items()))

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv)>1 else "search"
    if cmd == "search":
        # For each candidate base scenario profile, test whether the D3 flip tips the scenario.
        cands = ["BalancedContainerSecurityScenario","NISTCompliantScenario","CISCompliantScenario",
                 "OWASPCheatSheetCompliantScenario","OWASPTop10CompliantScenario","CICDSecurityScenario",
                 "RuntimeHardenedScenario","NetworkHardenedScenario","ImageSecurityFocusedScenario",
                 "EdgeComputingScenario","MicroservicesScenario","AirGappedScenario","ProductionScenario"]
        print(f"{'base profile':38s} {'B0 scenario':28s} -> {'after D3':28s}  flip?  Ptrace lik B0->D3")
        for c in cands:
            base = conf_from_profile(c)
            s0, a0 = actions(base)
            d3 = dict(base); d3.update(D3_FLIP)
            s1, a1 = actions(d3)
            flip = "YES" if s0!=s1 else "no"
            p0 = a0.get("ContainerPtraceInjection",("","","?"))[2]
            p1 = a1.get("ContainerPtraceInjection",("","","?"))[2]
            print(f"{c:38s} {s0:28s} -> {s1:28s}  {flip:4s}  {p0}->{p1}")
