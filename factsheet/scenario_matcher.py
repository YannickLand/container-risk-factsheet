"""
scenario_matcher.py — Determine the best-matching ContextScenario.

Mirrors ``DetermineBestMatchingScenario`` and ``CalculateScenarioFitScore``
from the Go reference implementation.
"""

from __future__ import annotations
from factsheet.risk_model import RiskModel, find_by_id, get_ref, get_ref_array
from factsheet.assumption_evaluator import (
    calculate_satisfaction_with_overrides,
    SATISFIED, UNKNOWN, DISSATISFIED,
    _get_ref_array,
)


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def find_best_scenario(
    model: RiskModel,
    trait_names: list[str],
    overrides: dict[str, str] | None = None,
) -> str:
    """
    Evaluate every scenario and return the @id of the best-matching one.

    Scoring per assumption in a scenario:
    - Expected == Calculated → 3 pts + perfectMatch counter++
    - Expected Satisfied, got Unknown → 1 pt
    - Expected Dissatisfied, got Unknown → 1 pt
    - Expected Unknown → 2 pts
    - Mismatch → 0 pts

    Tiebreak: most perfect matches.
    Returns empty string if no scenarios.
    """
    best_id = ""
    best_score = -1
    best_perfects = -1

    for scenario in model.scenarios:
        scenario_id: str = scenario.get("@id", "")
        if not scenario_id:
            continue
        score, perfects = _score_scenario(scenario_id, model, trait_names, overrides)
        if score > best_score or (score == best_score and perfects > best_perfects):
            best_score = score
            best_perfects = perfects
            best_id = scenario_id

    return best_id


def _score_scenario(
    scenario_id: str,
    model: RiskModel,
    trait_names: list[str],
    overrides: dict[str, str] | None,
) -> tuple[int, int]:
    """Return (total_score, perfect_matches) for one scenario."""
    scenario = find_by_id(scenario_id, model)
    if scenario is None:
        return 0, 0

    score = 0
    perfects = 0
    assumption_refs = _get_ref_array(scenario, "csro:includesAssumption")

    for ais_id in assumption_refs:
        ais_node = find_by_id(ais_id, model)
        if ais_node is None:
            continue

        for_assumption_id = get_ref(ais_node, "csro:forAssumption")
        if not for_assumption_id:
            continue

        for_assumption = find_by_id(for_assumption_id, model)
        if for_assumption is None:
            continue

        expected = _get_original_state(ais_node)
        calculated = calculate_satisfaction_with_overrides(
            for_assumption, trait_names, overrides
        )

        if expected == calculated:
            score += 3
            perfects += 1
        elif expected == SATISFIED and calculated == UNKNOWN:
            score += 1
        elif expected == DISSATISFIED and calculated == UNKNOWN:
            score += 1
        elif expected == UNKNOWN:
            score += 2
        # else: 0 — mismatch

    return score, perfects


def _get_original_state(ais_node: dict) -> str:
    """Extract the scenario's expected satisfaction state from AssumptionInScenario."""
    state_ref = ais_node.get("csro:hasSatisfactionState")
    if state_ref is None:
        return UNKNOWN
    if isinstance(state_ref, dict):
        state_id = state_ref.get("@id", "")
    elif isinstance(state_ref, str):
        state_id = state_ref
    else:
        return UNKNOWN
    # Strip prefix → "Satisfied", "Dissatisfied", "Unknown"
    if ":" in state_id:
        state_id = state_id.split(":", 1)[1]
    return state_id or UNKNOWN


# ---------------------------------------------------------------------------
# Build MatchingContextScenario output block
# ---------------------------------------------------------------------------

def build_matching_scenario_block(
    scenario_id: str,
    model: RiskModel,
    trait_names: list[str],
    overrides: dict[str, str] | None = None,
) -> dict:
    """
    Build the ``MatchingContextScenario`` section of the factsheet output.

    Structure matches demo/factsheet.json:
    {
        ScenarioDescription, ScenarioLabel,
        csro:includesAssumption [...],
        csro:includesComponent [...]
    }
    """
    scenario = find_by_id(scenario_id, model)
    if scenario is None:
        return {}

    label: str = scenario.get("rdfs:label", scenario.get("csro:label", ""))
    description: str = scenario.get("csro:description", "")

    # Build includesAssumption list
    includes_assumption: list[dict] = []
    for ais_id in _get_ref_array(scenario, "csro:includesAssumption"):
        ais_node = find_by_id(ais_id, model)
        if ais_node is None:
            continue

        for_assumption_id = get_ref(ais_node, "csro:forAssumption")
        for_assumption = (
            find_by_id(for_assumption_id, model) if for_assumption_id else None
        )

        # Expected state from scenario
        expected_state = _get_original_state(ais_node)
        state_id = f"csro:{expected_state}"

        entry: dict = {
            "@id": ais_id,
            "@type": "csro:AssumptionInScenario",
        }
        if for_assumption_id:
            entry["csro:forAssumption"] = {
                "@id": for_assumption_id,
                "@type": "csro:ContainerSecurityAssumption",
                "csro:assumptionId": (
                    for_assumption.get("csro:assumptionId", "")
                    if for_assumption else ""
                ),
            }
        entry["csro:hasSatisfactionState"] = {
            "@id": state_id,
            "@type": "csro:SatisfactionState",
        }
        includes_assumption.append(entry)

    # Build includesComponent list
    includes_component = _build_includes_component(scenario, model)

    return {
        "ScenarioDescription": description,
        "ScenarioLabel": label,
        "csro:includesAssumption": includes_assumption,
        "csro:includesComponent": includes_component,
    }


def _build_includes_component(scenario: dict, model: RiskModel) -> list[dict]:
    component_refs = _get_ref_array(scenario, "csro:includesComponent")
    result: list[dict] = []
    for comp_id in component_refs:
        comp_node = find_by_id(comp_id, model)
        if comp_node is None:
            result.append({"@id": comp_id})
            continue
        result.append({
            "@id": comp_node.get("@id", ""),
            "@type": comp_node.get("@type", "csro:Component"),
            "csro:description": comp_node.get("csro:description", ""),
            "rdfs:label": comp_node.get("rdfs:label", ""),
        })
    return result
