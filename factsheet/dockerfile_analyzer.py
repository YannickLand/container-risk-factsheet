"""
dockerfile_analyzer.py — Analyse Dockerfiles with Hadolint and produce deployment traits.

Hadolint (https://github.com/hadolint/hadolint) is an optional external binary.
When not available, analysis is skipped gracefully and only a
``dockerfile_analyzed`` trait with ``available: false`` is emitted.

Rule → trait mapping covers the most common Hadolint DL/SC rule codes.
"""

from __future__ import annotations
import json
import os
import subprocess
import tempfile


# ---------------------------------------------------------------------------
# Rule-ID → trait-ID mapping
# ---------------------------------------------------------------------------

_RULE_TO_TRAIT: dict[str, str] = {
    "DL3002": "dockerfile_root_user",
    "DL3004": "dockerfile_sudo_usage",
    "DL3005": "dockerfile_upgrade_packages",
    "DL3006": "dockerfile_untagged_image",
    "DL3007": "dockerfile_latest_tag",
    "DL3008": "dockerfile_unpinned_packages",
    "DL3009": "dockerfile_apt_cleanup",
    "DL3011": "dockerfile_invalid_port",
    "DL3013": "dockerfile_unpinned_packages",
    "DL3015": "dockerfile_recommended_packages",
    "DL3018": "dockerfile_unpinned_packages",
    "DL3019": "dockerfile_apk_cache",
    "DL3020": "dockerfile_add_vs_copy",
    "DL3025": "dockerfile_json_cmd_format",
    "DL3026": "dockerfile_invalid_base_image",
    "DL4000": "dockerfile_maintainer_deprecated",
    "DL4001": "dockerfile_wget_curl_both",
    "DL4006": "dockerfile_pipefail_missing",
    "SC2046": "dockerfile_unsafe_word_splitting",
    "SC2086": "dockerfile_unquoted_variable",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def is_hadolint_available() -> bool:
    """Return True if the ``hadolint`` binary is on PATH."""
    try:
        subprocess.run(
            ["hadolint", "--version"],
            capture_output=True,
            check=True,
            timeout=10,
        )
        return True
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False


def analyze_dockerfile(dockerfile_content: str, service_name: str) -> list[dict]:
    """
    Run Hadolint on *dockerfile_content* and return a list of trait dicts.

    Always emits a ``dockerfile_analyzed`` summary trait.
    Emits ``dockerfile_no_findings`` when Hadolint found zero issues.
    Emits one trait per distinct rule triggered (see ``_RULE_TO_TRAIT``).

    If Hadolint is not installed, returns a single ``dockerfile_analyzed``
    trait with ``"available": false`` and no per-rule traits.

    :param dockerfile_content: Raw text of the Dockerfile.
    :param service_name: Name of the compose service this Dockerfile belongs to.
    """
    if not is_hadolint_available():
        return [_make_analyzed_trait(service_name, available=False)]

    findings = _run_hadolint(dockerfile_content)
    return hadolint_findings_to_traits(findings, service_name)


def hadolint_findings_to_traits(
    findings: list[dict],
    service_name: str,
) -> list[dict]:
    """
    Convert a list of raw Hadolint JSON findings into deployment trait dicts.

    :param findings: List of dicts as returned by ``hadolint --format json``.
    :param service_name: Compose service name.
    """
    traits: list[dict] = []

    # --- Summary trait (always) ---
    error_count = sum(1 for f in findings if f.get("level") == "error")
    warning_count = sum(1 for f in findings if f.get("level") == "warning")
    info_count = sum(1 for f in findings if f.get("level") == "info")

    traits.append({
        "id": "dockerfile_analyzed",
        "name": "dockerfile_analyzed",
        "source": "dockerfile",
        "sourceDetails": {
            "service": service_name,
            "tool": "hadolint",
            "total_findings": len(findings),
            "error_count": error_count,
            "warning_count": warning_count,
            "info_count": info_count,
        },
        "type": "dockerfile_analysis",
    })

    if not findings:
        traits.append({
            "id": "dockerfile_no_findings",
            "name": "dockerfile_no_findings",
            "source": "dockerfile",
            "sourceDetails": {"service": service_name, "tool": "hadolint"},
            "type": "dockerfile_analysis",
        })
        return traits

    # --- Per-rule traits (one trait per distinct rule) ---
    seen_trait_ids: set[str] = set()
    rule_occurrences: dict[str, list] = {}
    for f in findings:
        rule_id = f.get("code", "")
        if rule_id:
            rule_occurrences.setdefault(rule_id, []).append(f)

    for rule_id, occs in rule_occurrences.items():
        trait_id = _RULE_TO_TRAIT.get(rule_id, f"dockerfile_{rule_id.lower()}")
        if trait_id in seen_trait_ids:
            continue
        seen_trait_ids.add(trait_id)

        lines = [o.get("line", 0) for o in occs]
        severity = occs[0].get("level", "warning")
        evidence = [
            f"Line {o.get('line', '?')}: {o.get('message', '')}" for o in occs
        ]

        traits.append({
            "id": trait_id,
            "name": trait_id,
            "source": "dockerfile",
            "sourceDetails": {
                "service": service_name,
                "tool": "hadolint",
                "rule_id": rule_id,
                "occurrences": len(occs),
                "lines": lines,
                "severity": severity,
                "evidence": evidence,
            },
            "type": "dockerfile_analysis",
        })

    return traits


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _run_hadolint(dockerfile_content: str) -> list[dict]:
    """Write content to a tmpfile, run hadolint, return parsed JSON findings."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".Dockerfile", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(dockerfile_content)
        tmp_path = tmp.name

    try:
        proc = subprocess.run(
            ["hadolint", "--format", "json", tmp_path],
            capture_output=True,
            text=True,
            timeout=30,
        )
        # hadolint exits 1 when findings exist — that is not a tool error
        raw = proc.stdout.strip()
        if not raw:
            return []
        return json.loads(raw)
    except (json.JSONDecodeError, subprocess.TimeoutExpired):
        return []
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def _make_analyzed_trait(service_name: str, *, available: bool) -> dict:
    return {
        "id": "dockerfile_analyzed",
        "name": "dockerfile_analyzed",
        "source": "dockerfile",
        "sourceDetails": {
            "service": service_name,
            "tool": "hadolint",
            "available": available,
        },
        "type": "dockerfile_analysis",
    }
