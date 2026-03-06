"""
treatment_report.py — Extract and summarise risk treatment actions from a factsheet.

A factsheet embeds treatment data inside each attack action::

    PossibleAttackActions[*]
      csro:causesImpact
        csro:indicates  (Risk node)
          csro:isTreatedBy[*]  (RiskTreatment nodes)

This module walks that structure, deduplicates treatments by ``@id``, and
groups them by the risk level of the attack action they address
(Critical → High → Moderate → Low).
"""

from __future__ import annotations

_LEVEL_ORDER = ["Critical", "High", "Moderate", "Low", "Unknown"]


def extract_treatments(factsheet: dict) -> dict:
    """
    Extract a risk treatment report from a generated factsheet.

    :param factsheet: The dict returned by :func:`generate_factsheet`.
    :returns: A report dict keyed by service name::

        {
          "service": {
            "summary": {"Critical": 2, "High": 1, "Moderate": 0, "Low": 0, "Unknown": 0},
            "treatments_by_level": {
              "Critical": [<treatment>, ...],
              "High": [...],
              ...
            },
            "all_treatments": [<treatment>, ...]   # deduplicated, ordered C→H→M→L
          }
        }
    """
    report: dict = {}
    for svc_name, svc_data in factsheet.items():
        attack_actions = svc_data.get("PossibleAttackActions", [])
        report[svc_name] = _extract_service_treatments(attack_actions)
    return report


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_service_treatments(attack_actions: list[dict]) -> dict:
    """Build a treatment report for one service."""
    # Map level → set of seen @ids (dedup) + list of treatment dicts
    by_level: dict[str, dict] = {
        level: {"seen": set(), "items": []} for level in _LEVEL_ORDER
    }

    for action in attack_actions:
        level = _get_risk_level(action)
        bucket = by_level.get(level) or by_level["Unknown"]
        treatments = _get_treatments(action)
        for t in treatments:
            tid = t.get("@id", "")
            if tid and tid in bucket["seen"]:
                continue
            if tid:
                bucket["seen"].add(tid)
            bucket["items"].append(t)

    treatments_by_level = {
        level: by_level[level]["items"]
        for level in _LEVEL_ORDER
        if by_level[level]["items"]
    }

    all_treatments: list[dict] = []
    for level in _LEVEL_ORDER:
        all_treatments.extend(by_level[level]["items"])

    summary = {level: len(by_level[level]["items"]) for level in _LEVEL_ORDER}

    return {
        "summary": summary,
        "treatments_by_level": treatments_by_level,
        "all_treatments": all_treatments,
    }


def _get_risk_level(action: dict) -> str:
    """Walk action → causesImpact → indicates → hasRiskLevel → @id."""
    impact = action.get("csro:causesImpact")
    if not isinstance(impact, dict):
        return "Unknown"
    risk = impact.get("csro:indicates")
    if not isinstance(risk, dict):
        return "Unknown"
    risk_level = risk.get("csro:hasRiskLevel")
    if isinstance(risk_level, dict):
        level_id = risk_level.get("@id", "")
        # e.g. "csro:CriticalRisk" → "Critical"
        for lvl in _LEVEL_ORDER:
            if lvl.lower() in level_id.lower():
                return lvl
    return "Unknown"


def _get_treatments(action: dict) -> list[dict]:
    """Walk action → causesImpact → indicates → isTreatedBy[]."""
    impact = action.get("csro:causesImpact")
    if not isinstance(impact, dict):
        return []
    risk = impact.get("csro:indicates")
    if not isinstance(risk, dict):
        return []
    treated_by = risk.get("csro:isTreatedBy", [])
    if isinstance(treated_by, dict):
        treated_by = [treated_by]
    return [t for t in treated_by if isinstance(t, dict)]
