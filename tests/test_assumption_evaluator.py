"""Tests for assumption_evaluator.py — pure logic, no risk model needed."""

import pytest
from factsheet.assumption_evaluator import (
    calculate_satisfaction,
    calculate_satisfaction_with_overrides,
    SATISFIED,
    UNKNOWN,
    DISSATISFIED,
)


def _make_assumption(
    assumption_id: str = "csro:TEST_1",
    verifiable_by: str | None = None,
    verifiable_by_absence: list[str] | None = None,
) -> dict:
    """Build a minimal assumption node for testing."""
    node: dict = {"@id": assumption_id, "@type": "csro:ContainerSecurityAssumption"}
    if verifiable_by:
        node["csro:isVerifiableBy"] = {"@id": verifiable_by}
    if verifiable_by_absence:
        node["csro:isVerifiableByAbsence"] = [{"@id": t} for t in verifiable_by_absence]
    return node


# ---------------------------------------------------------------------------
# No verification criteria
# ---------------------------------------------------------------------------

class TestNoVerificationCriteria:
    def test_no_criteria_returns_unknown(self):
        assumption = _make_assumption()
        assert calculate_satisfaction(assumption, []) == UNKNOWN

    def test_no_criteria_ignores_traits(self):
        assumption = _make_assumption()
        assert calculate_satisfaction(assumption, ["host_pid", "privileged_flag"]) == UNKNOWN


# ---------------------------------------------------------------------------
# IsVerifiableBy (required trait must be present)
# ---------------------------------------------------------------------------

class TestVerifiableBy:
    def test_required_trait_present_returns_satisfied(self):
        assumption = _make_assumption(verifiable_by="csro:read_only_filesystem")
        assert calculate_satisfaction(assumption, ["read_only_filesystem"]) == SATISFIED

    def test_required_trait_absent_returns_unknown(self):
        assumption = _make_assumption(verifiable_by="csro:read_only_filesystem")
        assert calculate_satisfaction(assumption, []) == UNKNOWN

    def test_required_trait_case_insensitive(self):
        assumption = _make_assumption(verifiable_by="csro:READ_ONLY_FILESYSTEM")
        assert calculate_satisfaction(assumption, ["read_only_filesystem"]) == SATISFIED


# ---------------------------------------------------------------------------
# IsVerifiableByAbsence (forbidden trait must be absent)
# ---------------------------------------------------------------------------

class TestVerifiableByAbsence:
    def test_forbidden_trait_absent_returns_satisfied(self):
        assumption = _make_assumption(verifiable_by_absence=["csro:external_network"])
        assert calculate_satisfaction(assumption, []) == SATISFIED

    def test_forbidden_trait_present_returns_dissatisfied(self):
        assumption = _make_assumption(verifiable_by_absence=["csro:external_network"])
        assert calculate_satisfaction(assumption, ["external_network"]) == DISSATISFIED

    def test_any_forbidden_trait_triggers_dissatisfied(self):
        assumption = _make_assumption(
            verifiable_by_absence=["csro:external_network", "csro:privileged_flag"]
        )
        assert calculate_satisfaction(assumption, ["privileged_flag"]) == DISSATISFIED

    def test_forbidden_trait_case_insensitive(self):
        assumption = _make_assumption(verifiable_by_absence=["csro:EXTERNAL_NETWORK"])
        assert calculate_satisfaction(assumption, ["external_network"]) == DISSATISFIED


# ---------------------------------------------------------------------------
# Overrides
# ---------------------------------------------------------------------------

class TestOverrides:
    def test_full_id_override_satisfied(self):
        assumption = _make_assumption("csro:NET_1")
        result = calculate_satisfaction_with_overrides(
            assumption, [], {"csro:NET_1": "Satisfied"}
        )
        assert result == SATISFIED

    def test_short_id_override(self):
        assumption = _make_assumption("csro:NET_1")
        result = calculate_satisfaction_with_overrides(
            assumption, [], {"NET_1": "Dissatisfied"}
        )
        assert result == DISSATISFIED

    def test_dash_id_override(self):
        assumption = _make_assumption("csro:NET_1")
        result = calculate_satisfaction_with_overrides(
            assumption, [], {"NET-1": "Unknown"}
        )
        assert result == UNKNOWN

    def test_category_prefix_override(self):
        assumption = _make_assumption("csro:NET_1")
        result = calculate_satisfaction_with_overrides(
            assumption, [], {"NET": "Satisfied"}
        )
        assert result == SATISFIED

    def test_override_case_insensitive(self):
        assumption = _make_assumption("csro:NET_1")
        result = calculate_satisfaction_with_overrides(
            assumption, [], {"NET_1": "satisfied"}
        )
        assert result == SATISFIED

    def test_no_override_falls_back_to_trait_logic(self):
        assumption = _make_assumption(verifiable_by="csro:read_only_filesystem")
        result = calculate_satisfaction_with_overrides(
            assumption, ["read_only_filesystem"], {}
        )
        assert result == SATISFIED

    def test_none_overrides_falls_back_to_trait_logic(self):
        assumption = _make_assumption(verifiable_by="csro:read_only_filesystem")
        result = calculate_satisfaction_with_overrides(
            assumption, [], None
        )
        assert result == UNKNOWN
