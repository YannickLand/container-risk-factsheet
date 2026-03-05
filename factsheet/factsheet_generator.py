"""
factsheet_generator.py — Orchestrate the full factsheet generation pipeline.

Usage::

    from factsheet.factsheet_generator import generate_factsheet
    import yaml

    with open("docker-compose.yml") as f:
        compose = yaml.safe_load(f)

    result = generate_factsheet(compose)
    # result is a dict keyed by service name, matching demo/factsheet.json
"""

from __future__ import annotations
import os
from typing import Any

import yaml

from factsheet.compose_normalizer import normalize_compose
from factsheet.trait_extractor import extract_all_traits
from factsheet.risk_model import (
    RiskModel,
    load_risk_model,
    find_by_id,
    get_ref,
    get_ref_array,
    strip_prefix,
    extract_trait_names,
    find_and_extract,
)
from factsheet.assumption_evaluator import (
    evaluate_all_assumptions,
    calculate_satisfaction_with_overrides,
    _get_ref_array as _ref_array,
)
from factsheet.scenario_matcher import (
    find_best_scenario,
    build_matching_scenario_block,
    _get_original_state,
)

_DEFAULT_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def generate_factsheet(
    compose: dict,
    overrides: dict[str, str] | None = None,
    data_dir: str | None = None,
) -> dict:
    """
    Generate a factsheet for every service in *compose*.

    :param compose: Parsed (but not yet normalised) docker-compose dict.
    :param overrides: Optional {assumption_id: "Satisfied|Unknown|Dissatisfied"}
                      manual override map.
    :param data_dir: Override path to the ``data/`` directory with risk model
                     files.  Defaults to ``../data`` relative to this file.
    :returns: ``{service_name: {ContainerSecurityAssumptionStates, ...}, ...}``
    """
    data_dir = data_dir or _DEFAULT_DATA_DIR
    overrides = overrides or {}

    # 1. Normalise compose
    normalised = normalize_compose(compose)

    # 2. Load risk model once
    model = load_risk_model(data_dir)

    # 3. Extract per-service traits
    per_service_traits = extract_all_traits(normalised)

    # 4. Build factsheet per service
    result: dict = {}
    for svc_name, traits in per_service_traits.items():
        trait_ids = [t["id"] for t in traits]

        # 4a. Evaluate assumptions
        assumption_states = evaluate_all_assumptions(model, trait_ids, overrides)

        # 4b. Find best matching scenario
        best_scenario_id = find_best_scenario(model, trait_ids, overrides)

        # 4c. Build matching scenario block
        matching_scenario = build_matching_scenario_block(
            best_scenario_id, model, trait_ids, overrides
        )

        # 4d. Find applicable attack actions
        attack_actions = find_matching_attack_actions(
            model, trait_ids, best_scenario_id
        )

        result[svc_name] = {
            "ContainerSecurityAssumptionStates": assumption_states,
            "DeploymentTraits": traits,
            "MatchingContextScenario": matching_scenario,
            "PossibleAttackActions": attack_actions,
        }

    return result


def generate_factsheet_from_file(
    compose_path: str,
    overrides: dict[str, str] | None = None,
    data_dir: str | None = None,
) -> dict:
    """Load a docker-compose file from disk and generate its factsheet."""
    with open(compose_path, "r", encoding="utf-8") as fh:
        compose = yaml.safe_load(fh)
    return generate_factsheet(compose, overrides=overrides, data_dir=data_dir)


# ---------------------------------------------------------------------------
# Attack action matching
# ---------------------------------------------------------------------------

def find_matching_attack_actions(
    model: RiskModel,
    trait_ids: list[str],
    scenario_id: str,
) -> list[dict]:
    """
    Return the attack actions that:
    1. Belong to *scenario_id* (via ``csro:inContext``).
    2. Have all ``csro:requiresTrait`` traits present in *trait_ids*.
    """
    trait_set = {t.lower() for t in trait_ids}
    matching: list[dict] = []

    for action in model.attack_actions:
        # Filter by scenario
        context_ref = get_ref(action, "csro:inContext")
        if context_ref != scenario_id:
            continue

        # Find technique node
        technique_ref = get_ref(action, "csro:appliesTechnique")
        if not technique_ref:
            matching.append(_build_attack_action_output(action, model))
            continue

        technique_node = find_by_id(technique_ref, model)
        if technique_node is None:
            continue

        # Check required traits
        required_refs = get_ref_array(technique_node, "csro:requiresTrait")
        required_names = extract_trait_names(required_refs)
        if not all(r.lower() in trait_set for r in required_names):
            continue

        matching.append(_build_attack_action_output(action, model))

    return matching


# ---------------------------------------------------------------------------
# Attack action output builder
# ---------------------------------------------------------------------------

def _build_attack_action_output(action: dict, model: RiskModel) -> dict:
    """Build the rich attack action dict for the factsheet output."""
    result: dict = {
        "@id": action.get("@id", ""),
        "@type": action.get("@type", "csro:AttackAction"),
        "csro:description": action.get("csro:description", ""),
    }

    # appliesTechnique — resolve with requiresTrait and referencesAttackTechnique
    tech_ref = get_ref(action, "csro:appliesTechnique")
    if tech_ref:
        tech_node = find_by_id(tech_ref, model)
        if tech_node is not None:
            result["csro:appliesTechnique"] = _build_technique(tech_node, model)

    # causesImpact
    impact_ref = get_ref(action, "csro:causesImpact")
    if impact_ref:
        impact_node = find_by_id(impact_ref, model)
        if impact_node is not None:
            result["csro:causesImpact"] = _build_impact(impact_node, model)

    # affects
    affects_refs = get_ref_array(action, "csro:affects")
    if affects_refs:
        result["csro:affects"] = [
            _resolve_component(r, model) for r in affects_refs
        ]

    # Ratings
    for rating_prop in (
        "csro:hasExploitabilityRating",
        "csro:hasExposureRating",
        "csro:hasLikelihood",
        "csro:inContext",
    ):
        _copy_ref_or_value(action, result, rating_prop, model)

    return result


def _build_technique(tech_node: dict, model: RiskModel) -> dict:
    out: dict = {
        "@id": tech_node.get("@id", ""),
        "@type": tech_node.get("@type", "csro:ContainerAttackTechnique"),
        "csro:description": tech_node.get("csro:description", ""),
    }

    # requiresTrait
    req_refs = get_ref_array(tech_node, "csro:requiresTrait")
    if req_refs:
        traits_out = []
        for ref in req_refs:
            t_node = find_by_id(ref, model)
            if t_node:
                traits_out.append({
                    "@id": t_node.get("@id", ""),
                    "@type": t_node.get("@type", "csro:ContainerDeploymentTrait"),
                    "csro:description": t_node.get("csro:description", ""),
                })
            else:
                traits_out.append({"@id": ref})
        out["csro:requiresTrait"] = traits_out

    # referencesAttackTechnique
    atk_ref = get_ref(tech_node, "csro:referencesAttackTechnique")
    if atk_ref:
        atk_node = find_by_id(atk_ref, model)
        if atk_node:
            out["csro:referencesAttackTechnique"] = {
                "@id": atk_node.get("@id", ""),
                "@type": atk_node.get("@type", "d3f:ATTACKEnterpriseTechnique"),
                "d3f:attack-id": atk_node.get("d3f:attack-id", ""),
                "d3f:definition": atk_node.get("d3f:definition", ""),
                "rdfs:label": atk_node.get("rdfs:label", ""),
            }

    return out


def _build_impact(impact_node: dict, model: RiskModel) -> dict:
    out: dict = {
        "@id": impact_node.get("@id", ""),
        "@type": impact_node.get("@type", "csro:Impact"),
        "csro:description": impact_node.get("csro:description", ""),
    }

    # hasImpactRating
    rating_ref = get_ref(impact_node, "csro:hasImpactRating")
    if rating_ref:
        r_node = find_by_id(rating_ref, model)
        if r_node:
            out["csro:hasImpactRating"] = {
                "@id": r_node.get("@id", ""),
                "@type": r_node.get("@type", "csro:ImpactRating"),
                "csro:description": r_node.get("csro:description", ""),
            }

    # indicates → Risk
    indicates_ref = get_ref(impact_node, "csro:indicates")
    if indicates_ref:
        risk_node = find_by_id(indicates_ref, model)
        if risk_node:
            out["csro:indicates"] = _build_risk(risk_node, model)

    return out


def _build_risk(risk_node: dict, model: RiskModel) -> dict:
    out: dict = {
        "@id": risk_node.get("@id", ""),
        "@type": risk_node.get("@type", "csro:Risk"),
        "csro:description": risk_node.get("csro:description", ""),
    }

    # hasRiskLevel
    rl_ref = get_ref(risk_node, "csro:hasRiskLevel")
    if rl_ref:
        rl_node = find_by_id(rl_ref, model)
        if rl_node:
            out["csro:hasRiskLevel"] = {
                "@id": rl_node.get("@id", ""),
                "@type": rl_node.get("@type", "csro:RiskLevel"),
                "rdfs:label": rl_node.get("rdfs:label", ""),
            }

    # isTreatedBy → list of treatments
    treated_by_refs = get_ref_array(risk_node, "csro:isTreatedBy")
    if not treated_by_refs:
        single = get_ref(risk_node, "csro:isTreatedBy")
        if single:
            treated_by_refs = [single]

    if treated_by_refs:
        treatments = []
        for t_ref in treated_by_refs:
            t_node = find_by_id(t_ref, model)
            if t_node:
                treatments.append(_build_treatment(t_node, model))
            else:
                treatments.append({"@id": t_ref})
        out["csro:isTreatedBy"] = treatments

    return out


def _build_treatment(t_node: dict, model: RiskModel) -> dict:
    out: dict = {
        "@id": t_node.get("@id", ""),
        "@type": t_node.get("@type", "csro:RiskTreatment"),
        "csro:description": t_node.get("csro:description", ""),
        "rdfs:label": t_node.get("rdfs:label", ""),
    }

    # addresses → assumption reference
    addr_ref = get_ref(t_node, "csro:addresses")
    if addr_ref:
        addr_node = find_by_id(addr_ref, model)
        if addr_node:
            out["csro:addresses"] = {
                "@id": addr_node.get("@id", ""),
                "@type": addr_node.get("@type", "csro:ContainerSecurityAssumption"),
                "csro:assumptionId": addr_node.get("csro:assumptionId", ""),
            }

    # hasGuideline
    gl_ref = get_ref(t_node, "csro:hasGuideline")
    if gl_ref:
        gl_node = find_by_id(gl_ref, model)
        if gl_node:
            out["csro:hasGuideline"] = {
                "@id": gl_node.get("@id", ""),
                "@type": gl_node.get("@type", "csro:ContainerSecurityGuideline"),
                "csro:description": gl_node.get("csro:description", ""),
                "rdfs:label": gl_node.get("rdfs:label", ""),
            }

    # isImplementedBy
    impl_refs = get_ref_array(t_node, "csro:isImplementedBy")
    if impl_refs:
        impls = []
        for impl_ref in impl_refs:
            impl_node = find_by_id(impl_ref, model)
            if impl_node:
                impls.append({
                    "@id": impl_node.get("@id", ""),
                    "@type": impl_node.get("@type", ""),
                    "csro:description": impl_node.get("csro:description", ""),
                    "rdfs:label": impl_node.get("rdfs:label", ""),
                })
        if impls:
            out["csro:isImplementedBy"] = impls

    return out


def _resolve_component(ref: str, model: RiskModel) -> dict:
    node = find_by_id(ref, model)
    if node is None:
        return {"@id": ref}
    return {
        "@id": node.get("@id", ""),
        "@type": node.get("@type", "csro:Component"),
        "csro:description": node.get("csro:description", ""),
        "rdfs:label": node.get("rdfs:label", ""),
    }


def _copy_ref_or_value(
    source: dict, dest: dict, prop: str, model: RiskModel
) -> None:
    """Copy a property from *source* to *dest*, resolving single-ref nodes."""
    val = source.get(prop)
    if val is None:
        return
    if isinstance(val, dict):
        ref = val.get("@id")
        if ref:
            node = find_by_id(ref, model)
            if node:
                dest[prop] = {k: v for k, v in node.items() if not k.startswith("@")}
                dest[prop]["@id"] = node.get("@id", "")
                dest[prop]["@type"] = node.get("@type", "")
                return
        dest[prop] = val
    elif isinstance(val, str):
        dest[prop] = {"@id": val}
    else:
        dest[prop] = val
