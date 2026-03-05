"""
assumption_evaluator.py — Evaluate satisfaction states for security assumptions.

Mirrors ``CalculateAssumptionSatisfaction`` and
``CalculateAssumptionSatisfactionWithOverrides`` from the Go reference.
"""

from __future__ import annotations
from factsheet.risk_model import (
    RiskModel,
    get_assumption_satisfaction_verifiers,
    find_by_id,
    get_ref,
    strip_prefix,
)

# Canonical state strings
SATISFIED = "Satisfied"
UNKNOWN = "Unknown"
DISSATISFIED = "Dissatisfied"

_STATE_ALIASES = {
    "satisfied": SATISFIED,
    "dissatisfied": DISSATISFIED,
    "unknown": UNKNOWN,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def calculate_satisfaction(
    assumption: dict,
    trait_names: list[str],
) -> str:
    """
    Determine satisfaction state for *assumption* given *trait_names*.

    Rules:
    - Any ``IsVerifiableByAbsence`` trait that IS present → Dissatisfied
    - All ``IsVerifiableBy`` traits present (and no forbidden) → Satisfied
    - Some ``IsVerifiableBy`` traits missing → Unknown
    - No verification criteria at all → Unknown
    - Only absence criteria and none triggered → Satisfied
    """
    required, forbidden = get_assumption_satisfaction_verifiers(assumption)
    trait_set = {t.lower() for t in trait_names}

    # Check forbidden (absence) traits
    for fbd in forbidden:
        if fbd.lower() in trait_set:
            return DISSATISFIED

    if not required and not forbidden:
        return UNKNOWN

    if required:
        all_present = all(r.lower() in trait_set for r in required)
        if all_present:
            return SATISFIED
        return UNKNOWN

    # required is empty but forbidden checks passed
    return SATISFIED


def calculate_satisfaction_with_overrides(
    assumption: dict,
    trait_names: list[str],
    overrides: dict[str, str] | None,
) -> str:
    """
    Like :func:`calculate_satisfaction` but honours manual overrides.

    Override keys may be in any of these formats (checked in priority order):
      1. Full IRI  ``csro:NET_2``
      2. Short underscore  ``NET_2``
      3. Dash variant  ``NET-2``
      4. Category prefix  ``NET``

    Override values are normalised to one of Satisfied / Unknown / Dissatisfied.
    """
    if overrides:
        assumption_id: str = assumption.get("@id", "")
        short_id = strip_prefix(assumption_id)
        dash_id = short_id.replace("_", "-")
        category = short_id.split("_")[0] if "_" in short_id else ""

        for key in (assumption_id, short_id, dash_id, category):
            if key and key in overrides:
                normalised = _STATE_ALIASES.get(overrides[key].lower())
                if normalised:
                    return normalised
                break

    return calculate_satisfaction(assumption, trait_names)


def evaluate_all_assumptions(
    model: RiskModel,
    trait_names: list[str],
    overrides: dict[str, str] | None = None,
) -> list[dict]:
    """
    Evaluate every unique ``ContainerSecurityAssumption`` in the model.

    Returns a list of analysis dicts, one per assumption:
    {
        AssumptionID, AssumptionDescription, AssumptionCategory,
        CalculatedSatisfactionState, RequiredTraits, AssumptionDetails
    }
    """
    seen: set[str] = set()
    results: list[dict] = []

    for scenario in model.scenarios:
        assumption_refs = _get_ref_array(scenario, "csro:includesAssumption")
        for ais_id in assumption_refs:
            ais_node = find_by_id(ais_id, model)
            if ais_node is None:
                continue

            for_assumption_id = get_ref(ais_node, "csro:forAssumption")
            if not for_assumption_id or for_assumption_id in seen:
                continue
            seen.add(for_assumption_id)

            assumption = find_by_id(for_assumption_id, model)
            if assumption is None:
                continue

            state = calculate_satisfaction_with_overrides(
                assumption, trait_names, overrides
            )

            required_traits = _build_required_traits_list(assumption)
            category_desc = _extract_category(assumption, model)
            assumption_details = _build_assumption_details(assumption, model)

            results.append({
                "AssumptionID": for_assumption_id,
                "AssumptionDescription": assumption.get("csro:description", ""),
                "AssumptionCategory": category_desc,
                "CalculatedSatisfactionState": state,
                "RequiredTraits": required_traits,
                "AssumptionDetails": assumption_details,
            })

    return results


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_ref_array(node: dict, prop: str) -> list[str]:
    """Extract list of @id strings from a property (handles single obj / list)."""
    val = node.get(prop)
    if val is None:
        return []
    if isinstance(val, str):
        return [val]
    if isinstance(val, dict):
        ref = val.get("@id")
        return [ref] if ref else []
    if isinstance(val, list):
        out = []
        for item in val:
            if isinstance(item, dict):
                r = item.get("@id")
                if r:
                    out.append(r)
            elif isinstance(item, str):
                out.append(item)
        return out
    return []


def _build_required_traits_list(assumption: dict) -> list[str] | None:
    """Return [trait, ...] list or None if no verifiers defined."""
    required, forbidden = get_assumption_satisfaction_verifiers(assumption)
    if not required and not forbidden:
        return None
    result = list(required)
    result += [f"{t}(absence)" for t in forbidden]
    return result if result else None


def _extract_category(assumption: dict, model: RiskModel) -> str:
    cat_ref = get_ref(assumption, "csro:belongsToCategory")
    if not cat_ref:
        return ""
    cat_node = find_by_id(cat_ref, model)
    if cat_node is None:
        return ""
    return cat_node.get("csro:description", "")


def _build_assumption_details(assumption: dict, model: RiskModel) -> dict:
    """
    Build the minimal AssumptionDetails dict that matches the demo output.

    Includes: @id, @type, csro:assumptionId, csro:belongsToCategory,
              csro:description, csro:originatesFrom
    """
    details: dict = {
        "@id": assumption.get("@id", ""),
        "@type": assumption.get("@type", "csro:ContainerSecurityAssumption"),
        "csro:assumptionId": assumption.get("csro:assumptionId", ""),
        "csro:description": assumption.get("csro:description", ""),
    }

    # Category
    cat_ref = get_ref(assumption, "csro:belongsToCategory")
    if cat_ref:
        cat_node = find_by_id(cat_ref, model)
        if cat_node:
            details["csro:belongsToCategory"] = {
                "@id": cat_node.get("@id", ""),
                "@type": cat_node.get("@type", "csro:AssumptionCategory"),
                "csro:description": cat_node.get("csro:description", ""),
                "rdfs:label": cat_node.get("rdfs:label", ""),
            }

    # Standard sections (originatesFrom)
    section_refs = _get_ref_array(assumption, "csro:originatesFrom")
    origins: list[dict] = []
    for sec_id in section_refs:
        sec_node = find_by_id(sec_id, model)
        if sec_node is None:
            origins.append({"@id": sec_id})
            continue
        standards_origin: dict = {
            "@id": sec_node.get("@id", ""),
            "@type": sec_node.get("@type", "csro:ContainerSecurityStandardSection"),
            "csro:sectionId": sec_node.get("csro:sectionId", ""),
        }
        std_ref = get_ref(sec_node, "csro:belongsToStandard")
        if std_ref:
            std_node = find_by_id(std_ref, model)
            if std_node:
                standards_origin["csro:belongsToStandard"] = {
                    "@id": std_node.get("@id", ""),
                    "@type": std_node.get("@type", "csro:ContainerSecurityStandard"),
                    "csro:description": std_node.get("csro:description", ""),
                    "rdfs:label": std_node.get("rdfs:label", ""),
                }
        origins.append(standards_origin)

    if origins:
        details["csro:originatesFrom"] = origins

    return details
