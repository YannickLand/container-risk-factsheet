"""Tests for factsheet/treatment_report.py — pure logic, no external deps."""

import pytest
from factsheet.treatment_report import (
    extract_treatments,
    _extract_service_treatments,
    _get_risk_level,
    _get_treatments,
)


# ---------------------------------------------------------------------------
# Helpers for building test data
# ---------------------------------------------------------------------------

def _make_treatment(tid: str, label: str = "") -> dict:
    return {
        "@id": tid,
        "@type": "csro:RiskTreatment",
        "rdfs:label": label or tid,
    }


def _make_risk(level_id: str, treatments: list[dict] | None = None) -> dict:
    node: dict = {
        "@id": f"csro:Risk_{level_id}",
        "@type": "csro:Risk",
        "csro:hasRiskLevel": {"@id": f"csro:{level_id}Risk"},
    }
    if treatments:
        node["csro:isTreatedBy"] = treatments
    return node


def _make_action(risk: dict | None = None) -> dict:
    action: dict = {"@id": "csro:ExampleAction", "@type": "csro:AttackAction"}
    if risk is not None:
        action["csro:causesImpact"] = {"csro:indicates": risk}
    return action


# ---------------------------------------------------------------------------
# _get_risk_level
# ---------------------------------------------------------------------------

class TestGetRiskLevel:
    def test_critical(self):
        action = _make_action(_make_risk("Critical"))
        assert _get_risk_level(action) == "Critical"

    def test_high(self):
        action = _make_action(_make_risk("High"))
        assert _get_risk_level(action) == "High"

    def test_moderate(self):
        action = _make_action(_make_risk("Moderate"))
        assert _get_risk_level(action) == "Moderate"

    def test_low(self):
        action = _make_action(_make_risk("Low"))
        assert _get_risk_level(action) == "Low"

    def test_unknown_when_no_impact(self):
        action = {"@id": "csro:NoImpact"}
        assert _get_risk_level(action) == "Unknown"

    def test_unknown_when_no_indicates(self):
        action = {"csro:causesImpact": {}}
        assert _get_risk_level(action) == "Unknown"

    def test_unknown_when_no_has_risk_level(self):
        action = _make_action({"@id": "csro:R1"})
        assert _get_risk_level(action) == "Unknown"

    def test_level_is_case_insensitive(self):
        # The helper does ".lower() in level_id.lower()"
        action = _make_action({"csro:hasRiskLevel": {"@id": "csro:criticalrisk"}})
        assert _get_risk_level(action) == "Critical"


# ---------------------------------------------------------------------------
# _get_treatments
# ---------------------------------------------------------------------------

class TestGetTreatments:
    def test_returns_list_of_treatments(self):
        t1 = _make_treatment("csro:T1")
        t2 = _make_treatment("csro:T2")
        action = _make_action(_make_risk("Critical", [t1, t2]))
        result = _get_treatments(action)
        assert len(result) == 2
        assert result[0]["@id"] == "csro:T1"

    def test_single_dict_wrapped_as_list(self):
        t1 = _make_treatment("csro:T1")
        risk = _make_risk("High")
        risk["csro:isTreatedBy"] = t1  # single dict, not a list
        action = _make_action(risk)
        result = _get_treatments(action)
        assert result == [t1]

    def test_empty_when_no_impact(self):
        action = {"@id": "csro:NoImpact"}
        assert _get_treatments(action) == []

    def test_empty_when_no_treated_by(self):
        action = _make_action(_make_risk("Low"))
        assert _get_treatments(action) == []


# ---------------------------------------------------------------------------
# _extract_service_treatments
# ---------------------------------------------------------------------------

class TestExtractServiceTreatments:
    def test_counts_grouped_by_level(self):
        t1 = _make_treatment("csro:T1")
        t2 = _make_treatment("csro:T2")
        t3 = _make_treatment("csro:T3")
        actions = [
            _make_action(_make_risk("Critical", [t1])),
            _make_action(_make_risk("Critical", [t2])),
            _make_action(_make_risk("High", [t3])),
        ]
        result = _extract_service_treatments(actions)
        assert result["summary"]["Critical"] == 2
        assert result["summary"]["High"] == 1
        assert result["summary"]["Low"] == 0

    def test_deduplicates_by_id(self):
        t1 = _make_treatment("csro:T1")
        actions = [
            _make_action(_make_risk("Critical", [t1])),
            _make_action(_make_risk("Critical", [t1])),  # duplicate @id
        ]
        result = _extract_service_treatments(actions)
        assert result["summary"]["Critical"] == 1
        assert len(result["all_treatments"]) == 1

    def test_level_ordering_in_all_treatments(self):
        t_low = _make_treatment("csro:TLow")
        t_critical = _make_treatment("csro:TCritical")
        actions = [
            _make_action(_make_risk("Low", [t_low])),
            _make_action(_make_risk("Critical", [t_critical])),
        ]
        result = _extract_service_treatments(actions)
        ids = [t["@id"] for t in result["all_treatments"]]
        # Critical before Low
        assert ids.index("csro:TCritical") < ids.index("csro:TLow")

    def test_empty_actions_returns_zero_summary(self):
        result = _extract_service_treatments([])
        assert all(v == 0 for v in result["summary"].values())
        assert result["all_treatments"] == []
        assert result["treatments_by_level"] == {}

    def test_treatments_by_level_omits_empty_levels(self):
        t1 = _make_treatment("csro:T1")
        actions = [_make_action(_make_risk("High", [t1]))]
        result = _extract_service_treatments(actions)
        assert "High" in result["treatments_by_level"]
        assert "Critical" not in result["treatments_by_level"]
        assert "Low" not in result["treatments_by_level"]


# ---------------------------------------------------------------------------
# extract_treatments (top-level)
# ---------------------------------------------------------------------------

class TestExtractTreatments:
    def test_keyed_by_service_name(self):
        t1 = _make_treatment("csro:T1")
        factsheet = {
            "web": {"PossibleAttackActions": [_make_action(_make_risk("High", [t1]))]},
            "db": {"PossibleAttackActions": []},
        }
        report = extract_treatments(factsheet)
        assert "web" in report
        assert "db" in report

    def test_missing_possible_attack_actions_key(self):
        factsheet = {"svc": {}}
        report = extract_treatments(factsheet)
        assert report["svc"]["all_treatments"] == []

    def test_single_service_full_path(self):
        t1 = _make_treatment("csro:T_Critical", "Fix critical issue")
        t2 = _make_treatment("csro:T_Low", "Low priority fix")
        factsheet = {
            "myservice": {
                "PossibleAttackActions": [
                    _make_action(_make_risk("Critical", [t1])),
                    _make_action(_make_risk("Low", [t2])),
                ]
            }
        }
        report = extract_treatments(factsheet)
        svc = report["myservice"]
        assert svc["summary"]["Critical"] == 1
        assert svc["summary"]["Low"] == 1
        assert len(svc["all_treatments"]) == 2
        assert "Critical" in svc["treatments_by_level"]
        assert "Low" in svc["treatments_by_level"]
