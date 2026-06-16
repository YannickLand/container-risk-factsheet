#!/usr/bin/env python3
"""
analyze.py — Summarise and diff Container Risk Factsheets for the Delta Experiment.

Usage:
  python analyze.py summary <factsheet.json> [--service NAME]
  python analyze.py hash    <factsheet.json>
  python analyze.py diff    <before.json> <after.json> --delta-id D1 [--service NAME]

All output is deterministic (keys sorted). The factsheet contains no volatile
fields (no timestamps/paths/run-ids), so the canonical hash is sha256 over
json.dumps(obj, sort_keys=True, ensure_ascii=False).
"""
from __future__ import annotations
import json
import sys
import hashlib
import argparse


def load(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def canonical_bytes(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False).encode("utf-8")


def canonical_hash(obj) -> str:
    return hashlib.sha256(canonical_bytes(obj)).hexdigest()


def _id(node):
    """Return the @id of a node/ref, or '' """
    if isinstance(node, dict):
        return node.get("@id", "")
    if isinstance(node, str):
        return node
    return ""


def first_service(fs: dict, service: str | None) -> tuple[str, dict]:
    if service:
        return service, fs[service]
    name = next(iter(fs))
    return name, fs[name]


def action_view(action: dict) -> dict:
    """Flatten one PossibleAttackAction to the dimensions we track."""
    tech = action.get("csro:appliesTechnique", {})
    impact = action.get("csro:causesImpact", {})
    impact_rating = ""
    risk_level = ""
    risk_id = ""
    if isinstance(impact, dict):
        impact_rating = _id(impact.get("csro:hasImpactRating", {}))
        indicates = impact.get("csro:indicates", {})
        if isinstance(indicates, dict):
            risk_id = indicates.get("@id", "")
            risk_level = _id(indicates.get("csro:hasRiskLevel", {}))
    return {
        "action_id": action.get("@id", ""),
        "technique": _id(tech),
        "exploitability": _id(action.get("csro:hasExploitabilityRating", {})),
        "exposure": _id(action.get("csro:hasExposureRating", {})),
        "likelihood": _id(action.get("csro:hasLikelihood", {})),
        "impact_node": _id(impact),
        "impact_rating": impact_rating,
        "risk_id": risk_id,
        "risk_level": risk_level,
    }


def summarise(fs: dict, service: str | None) -> dict:
    name, svc = first_service(fs, service)
    states = svc.get("ContainerSecurityAssumptionStates", [])
    counts = {"Satisfied": 0, "Unknown": 0, "Dissatisfied": 0}
    for s in states:
        st = s.get("CalculatedSatisfactionState", "")
        counts[st] = counts.get(st, 0) + 1
    scenario = svc.get("MatchingContextScenario", {})
    actions = [action_view(a) for a in svc.get("PossibleAttackActions", [])]
    traits = sorted({t.get("id", "") for t in svc.get("DeploymentTraits", [])})
    return {
        "service": name,
        "scenario_label": scenario.get("ScenarioLabel", ""),
        "scenario_id": scenario.get("@id", ""),  # usually absent
        "assumption_total": len(states),
        "assumption_counts": counts,
        "actions_count": len(actions),
        "actions": actions,
        "trait_ids": traits,
    }


def cmd_summary(args):
    fs = load(args.path)
    summ = summarise(fs, args.service)
    print(json.dumps(summ, indent=2, ensure_ascii=False, sort_keys=True))
    # Human-readable action table
    print("\n# Scenario:", summ["scenario_label"])
    print("# Assumptions:", summ["assumption_total"], summ["assumption_counts"])
    print(f"# Attack actions ({summ['actions_count']}):")
    for a in summ["actions"]:
        print(f"  - {short(a['technique']):45s} expl={short(a['exploitability']):24s} "
              f"expo={short(a['exposure']):24s} lik={short(a['likelihood']):22s} "
              f"impact={short(a['impact_rating']):10s} risk={short(a['risk_level'])}")


def short(s: str) -> str:
    return s.split(":")[-1] if s else "-"


def cmd_hash(args):
    fs = load(args.path)
    print(canonical_hash(fs))


def cmd_diff(args):
    before = summarise(load(args.before), args.service)
    after = summarise(load(args.after), args.service)

    b_actions = {a["action_id"]: a for a in before["actions"]}
    a_actions = {a["action_id"]: a for a in after["actions"]}

    removed = sorted(set(b_actions) - set(a_actions))
    added = sorted(set(a_actions) - set(b_actions))
    common = sorted(set(b_actions) & set(a_actions))

    rating_changes = []
    impact_changes = []
    unchanged_actions = []
    for aid in common:
        b = b_actions[aid]
        a = a_actions[aid]
        dims_changed = {}
        for dim in ("exploitability", "exposure", "likelihood", "risk_level"):
            if b[dim] != a[dim]:
                dims_changed[dim] = [b[dim], a[dim]]
        if b["impact_rating"] != a["impact_rating"]:
            impact_changes.append({
                "action": aid,
                "technique": b["technique"],
                "impact_node": b["impact_node"],
                "impact_rating": [b["impact_rating"], a["impact_rating"]],
            })
        if dims_changed:
            entry = {"technique": b["technique"], "action_id": aid}
            for dim in ("exploitability", "exposure", "likelihood", "risk_level"):
                entry[dim] = dims_changed.get(dim, [b[dim], a[dim]] if False else None)
            # only include dims that actually changed for compactness
            entry = {"technique": b["technique"], "action_id": aid, **dims_changed}
            rating_changes.append(entry)
        else:
            unchanged_actions.append(b["technique"])

    diff = {
        "delta_id": args.delta_id,
        "scenario": {"before": before["scenario_label"], "after": after["scenario_label"]},
        "assumption_counts": {"before": before["assumption_counts"], "after": after["assumption_counts"]},
        "actions_removed": [b_actions[a]["technique"] for a in removed],
        "actions_added": [a_actions[a]["technique"] for a in added],
        "rating_changes": rating_changes,
        "impact_changes": impact_changes,
        "unchanged_actions": sorted(unchanged_actions),
        "notes": "",
    }
    print(json.dumps(diff, indent=2, ensure_ascii=False, sort_keys=True))


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)

    ps = sub.add_parser("summary")
    ps.add_argument("path")
    ps.add_argument("--service", default=None)
    ps.set_defaults(func=cmd_summary)

    ph = sub.add_parser("hash")
    ph.add_argument("path")
    ph.set_defaults(func=cmd_hash)

    pd = sub.add_parser("diff")
    pd.add_argument("before")
    pd.add_argument("after")
    pd.add_argument("--delta-id", required=True)
    pd.add_argument("--service", default=None)
    pd.set_defaults(func=cmd_diff)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
