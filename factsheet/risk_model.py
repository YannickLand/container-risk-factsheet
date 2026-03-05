"""
risk_model.py — Load and navigate the CSRO risk knowledge graph.

The graph is stored in ``data/tra_model/query_results/15_full_csro/risk_export.jsonld``
as a JSON-LD ``@graph`` array.  This module parses it into an indexed
in-memory structure and exposes helper methods that mirror the Go reference.
"""

from __future__ import annotations
import json
import os
from dataclasses import dataclass, field
from typing import Any

_CSRO_PREFIX = "csro:"
_DEFAULT_DATA_DIR = os.path.join(
    os.path.dirname(__file__), "..", "data"
)


# ---------------------------------------------------------------------------
# Data class
# ---------------------------------------------------------------------------

@dataclass
class RiskModel:
    """Parsed risk knowledge graph with indexed node lookup."""

    # All nodes indexed by @id
    _index: dict[str, dict] = field(default_factory=dict, repr=False)

    # Convenience node lists (populated during parse)
    scenarios: list[dict] = field(default_factory=list, repr=False)
    attack_actions: list[dict] = field(default_factory=list, repr=False)
    assumptions: list[dict] = field(default_factory=list, repr=False)
    techniques: list[dict] = field(default_factory=list, repr=False)

    # Full raw graph
    graph: list[dict] = field(default_factory=list, repr=False)


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def load_risk_model(data_dir: str | None = None) -> RiskModel:
    """Load ``risk_export.jsonld`` from *data_dir* and return a :class:`RiskModel`."""
    data_dir = data_dir or _DEFAULT_DATA_DIR
    path = os.path.join(
        data_dir, "tra_model", "query_results", "15_full_csro", "risk_export.jsonld"
    )
    with open(path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)

    model = RiskModel()
    graph_nodes: list[dict] = raw.get("@graph", [])
    model.graph = graph_nodes

    for node in graph_nodes:
        node_id: str = node.get("@id", "")
        if node_id:
            model._index[node_id] = node

        node_type = node.get("@type", "")
        if node_type == "csro:ContextScenario":
            model.scenarios.append(node)
        elif node_type == "csro:AttackAction":
            model.attack_actions.append(node)
        elif node_type == "csro:ContainerSecurityAssumption":
            model.assumptions.append(node)
        elif node_type == "csro:ContainerAttackTechnique":
            model.techniques.append(node)

    return model


def load_rule_model(data_dir: str | None = None) -> dict:
    """Load ``rule_export.jsonld`` and return the raw parsed dict."""
    data_dir = data_dir or _DEFAULT_DATA_DIR
    path = os.path.join(
        data_dir, "tra_model", "query_results", "15_full_csro", "rule_export.jsonld"
    )
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


# ---------------------------------------------------------------------------
# Graph traversal helpers  (mirrors Go helper functions)
# ---------------------------------------------------------------------------

def find_by_id(node_id: str, model: RiskModel) -> dict | None:
    """Return the node with the given ``@id`` or ``None``."""
    return model._index.get(node_id)


def get_ref(node: dict, prop: str) -> str:
    """
    Extract a single ``@id`` reference from a property that may be either:
      • ``{"@id": "..."}``
      • a plain string  ``"..."``
      • absent / None

    Returns empty string when not found.
    """
    val = node.get(prop)
    if val is None:
        return ""
    if isinstance(val, dict):
        return val.get("@id", "")
    if isinstance(val, str):
        return val
    # List: take first element
    if isinstance(val, list) and val:
        return get_ref({"_": val[0]}, "_")
    return ""


def get_ref_array(node: dict, prop: str) -> list[str]:
    """
    Extract a list of ``@id`` references from a property that may be either:
      • ``[{"@id": "..."}, ...]``
      • ``{"@id": "..."}``
      • ``["id1", "id2", ...]``
      • absent / None
    Returns a (possibly empty) list of ID strings.
    """
    val = node.get(prop)
    if val is None:
        return []
    if isinstance(val, str):
        return [val]
    if isinstance(val, dict):
        ref = val.get("@id")
        return [ref] if ref else []
    if isinstance(val, list):
        result = []
        for item in val:
            if isinstance(item, dict):
                ref = item.get("@id")
                if ref:
                    result.append(ref)
            elif isinstance(item, str):
                result.append(item)
        return result
    return []


def strip_prefix(s: str) -> str:
    """Remove the ``csro:`` prefix from an identifier."""
    if s.startswith(_CSRO_PREFIX):
        return s[len(_CSRO_PREFIX):]
    return s


def extract_trait_names(refs: list[str]) -> list[str]:
    """Convert a list of ``csro:trait_name`` refs to bare trait name strings."""
    return [strip_prefix(r) for r in refs if r]


def find_and_extract(node_id: str, model: RiskModel, _visited: set[str] | None = None) -> dict | None:
    """
    Find a node by ID and return a deep-resolved copy (replacing ``@id`` refs
    with full node bodies, one level deep to avoid cycles).
    """
    if _visited is None:
        _visited = set()
    if node_id in _visited:
        return find_by_id(node_id, model)
    _visited.add(node_id)

    node = find_by_id(node_id, model)
    if node is None:
        return None

    resolved: dict = {}
    for key, val in node.items():
        resolved[key] = _resolve_value(val, model, _visited)
    return resolved


def _resolve_value(val: Any, model: RiskModel, visited: set[str]) -> Any:
    if isinstance(val, dict):
        ref_id = val.get("@id")
        if ref_id and len(val) == 1:
            # Pure reference — expand it
            expanded = find_and_extract(ref_id, model, visited)
            return expanded if expanded is not None else val
        # Dict with content — recurse
        return {k: _resolve_value(v, model, visited) for k, v in val.items()}
    if isinstance(val, list):
        return [_resolve_value(item, model, visited) for item in val]
    return val


# ---------------------------------------------------------------------------
# Convenience: extract trait names from an assumption node
# ---------------------------------------------------------------------------

def get_assumption_required_traits(assumption: dict) -> list[str]:
    """
    Return the list of trait names required to satisfy an assumption,
    in the form ``["trait_name", "other_trait(absence)", ...]``.

    Positive  (IsVerifiableBy) → ``"trait_name"``
    Negative  (IsVerifiableByAbsence) → ``"trait_name(absence)"``
    """
    result: list[str] = []

    by_ref = get_ref(assumption, "csro:isVerifiableBy")
    if by_ref:
        result.append(strip_prefix(by_ref))

    absence_refs = get_ref_array(assumption, "csro:isVerifiableByAbsence")
    for ref in absence_refs:
        result.append(strip_prefix(ref) + "(absence)")

    return result or None  # None = not verifiable


def get_assumption_satisfaction_verifiers(assumption: dict) -> tuple[list[str], list[str]]:
    """
    Return ``(required_traits, forbidden_traits)`` where:
    - *required_traits* must ALL be present for ``Satisfied``
    - *forbidden_traits* must ALL be absent for ``Satisfied``
    """
    required: list[str] = []
    forbidden: list[str] = []

    # IsVerifiableBy can be single ref or array (in practice single)
    by_refs = get_ref_array(assumption, "csro:isVerifiableBy")
    if not by_refs:
        single = get_ref(assumption, "csro:isVerifiableBy")
        if single:
            by_refs = [single]
    required = [strip_prefix(r) for r in by_refs if r]

    absence_refs = get_ref_array(assumption, "csro:isVerifiableByAbsence")
    forbidden = [strip_prefix(r) for r in absence_refs if r]

    return required, forbidden
