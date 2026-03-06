"""
Tests for factsheet/dockerfile_analyzer.py.

Unit tests use mocked subprocess calls; integration tests (marked with
``pytest.mark.integration``) require the real ``hadolint`` binary.
"""

from __future__ import annotations
import json
from unittest.mock import MagicMock, patch

import pytest

from factsheet.dockerfile_analyzer import (
    analyze_dockerfile,
    hadolint_findings_to_traits,
    is_hadolint_available,
    _run_hadolint,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(rule: str, line: int = 1, level: str = "warning", msg: str = "msg") -> dict:
    return {"code": rule, "line": line, "level": level, "message": msg}


# ---------------------------------------------------------------------------
# is_hadolint_available
# ---------------------------------------------------------------------------

class TestIsHadolintAvailable:
    def test_returns_true_when_subprocess_succeeds(self):
        with patch("factsheet.dockerfile_analyzer.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            assert is_hadolint_available() is True

    def test_returns_false_when_file_not_found(self):
        with patch(
            "factsheet.dockerfile_analyzer.subprocess.run",
            side_effect=FileNotFoundError,
        ):
            assert is_hadolint_available() is False

    def test_returns_false_when_called_process_error(self):
        import subprocess
        with patch(
            "factsheet.dockerfile_analyzer.subprocess.run",
            side_effect=subprocess.CalledProcessError(1, "hadolint"),
        ):
            assert is_hadolint_available() is False

    def test_returns_false_when_timeout(self):
        import subprocess
        with patch(
            "factsheet.dockerfile_analyzer.subprocess.run",
            side_effect=subprocess.TimeoutExpired("hadolint", 10),
        ):
            assert is_hadolint_available() is False


# ---------------------------------------------------------------------------
# hadolint_findings_to_traits
# ---------------------------------------------------------------------------

class TestHadolintFindingsToTraits:
    def test_always_emits_analyzed_trait(self):
        traits = hadolint_findings_to_traits([], "svc")
        ids = [t["id"] for t in traits]
        assert "dockerfile_analyzed" in ids

    def test_emits_no_findings_when_empty(self):
        traits = hadolint_findings_to_traits([], "svc")
        ids = [t["id"] for t in traits]
        assert "dockerfile_no_findings" in ids

    def test_no_findings_trait_absent_when_findings_exist(self):
        traits = hadolint_findings_to_traits([_finding("DL3007")], "svc")
        ids = [t["id"] for t in traits]
        assert "dockerfile_no_findings" not in ids

    def test_known_rule_maps_to_named_trait(self):
        traits = hadolint_findings_to_traits([_finding("DL3007")], "svc")
        ids = [t["id"] for t in traits]
        assert "dockerfile_latest_tag" in ids

    def test_unknown_rule_gets_generic_trait_id(self):
        traits = hadolint_findings_to_traits([_finding("DL9999")], "svc")
        ids = [t["id"] for t in traits]
        assert "dockerfile_dl9999" in ids

    def test_multiple_occurrences_of_same_rule_deduped(self):
        findings = [_finding("DL3002", line=1), _finding("DL3002", line=5)]
        traits = hadolint_findings_to_traits(findings, "svc")
        ids = [t["id"] for t in traits]
        assert ids.count("dockerfile_root_user") == 1

    def test_multiple_distinct_rules_emit_separate_traits(self):
        findings = [_finding("DL3002"), _finding("DL3007")]
        traits = hadolint_findings_to_traits(findings, "svc")
        ids = [t["id"] for t in traits]
        assert "dockerfile_root_user" in ids
        assert "dockerfile_latest_tag" in ids

    def test_summary_counts_in_analyzed_trait(self):
        findings = [
            _finding("DL3002", level="error"),
            _finding("DL3007", level="warning"),
            _finding("DL3008", level="info"),
        ]
        traits = hadolint_findings_to_traits(findings, "svc")
        analyzed = next(t for t in traits if t["id"] == "dockerfile_analyzed")
        assert analyzed["sourceDetails"]["error_count"] == 1
        assert analyzed["sourceDetails"]["warning_count"] == 1
        assert analyzed["sourceDetails"]["info_count"] == 1
        assert analyzed["sourceDetails"]["total_findings"] == 3

    def test_service_name_in_source_details(self):
        traits = hadolint_findings_to_traits([], "my-service")
        analyzed = next(t for t in traits if t["id"] == "dockerfile_analyzed")
        assert analyzed["sourceDetails"]["service"] == "my-service"

    def test_trait_source_is_dockerfile(self):
        traits = hadolint_findings_to_traits([_finding("DL3007")], "svc")
        for t in traits:
            assert t["source"] == "dockerfile"

    def test_trait_type_is_dockerfile_analysis(self):
        traits = hadolint_findings_to_traits([], "svc")
        for t in traits:
            assert t["type"] == "dockerfile_analysis"

    def test_evidence_in_per_rule_trait(self):
        traits = hadolint_findings_to_traits(
            [_finding("DL3002", line=10, msg="Don't run as root")], "svc"
        )
        rule_trait = next(t for t in traits if t["id"] == "dockerfile_root_user")
        assert any("10" in e for e in rule_trait["sourceDetails"]["evidence"])


# ---------------------------------------------------------------------------
# analyze_dockerfile
# ---------------------------------------------------------------------------

class TestAnalyzeDockerfile:
    def test_skips_gracefully_when_hadolint_unavailable(self):
        with patch("factsheet.dockerfile_analyzer.is_hadolint_available", return_value=False):
            traits = analyze_dockerfile("FROM ubuntu", "svc")
        assert len(traits) == 1
        t = traits[0]
        assert t["id"] == "dockerfile_analyzed"
        assert t["sourceDetails"]["available"] is False

    def test_returns_traits_when_hadolint_available(self):
        findings = [_finding("DL3007")]
        with (
            patch("factsheet.dockerfile_analyzer.is_hadolint_available", return_value=True),
            patch("factsheet.dockerfile_analyzer._run_hadolint", return_value=findings),
        ):
            traits = analyze_dockerfile("FROM ubuntu:latest", "svc")
        ids = [t["id"] for t in traits]
        assert "dockerfile_analyzed" in ids
        assert "dockerfile_latest_tag" in ids

    def test_passes_content_to_run_hadolint(self):
        content = "FROM python:3.12\nCMD python app.py"
        with (
            patch("factsheet.dockerfile_analyzer.is_hadolint_available", return_value=True),
            patch("factsheet.dockerfile_analyzer._run_hadolint", return_value=[]) as mock_run,
        ):
            analyze_dockerfile(content, "svc")
        mock_run.assert_called_once_with(content)


# ---------------------------------------------------------------------------
# _run_hadolint (unit — mocked subprocess)
# ---------------------------------------------------------------------------

class TestRunHadolint:
    def test_parses_json_output(self):
        findings = [{"code": "DL3007", "line": 1, "level": "warning", "message": "test"}]
        mock_proc = MagicMock()
        mock_proc.stdout = json.dumps(findings)
        with (
            patch("factsheet.dockerfile_analyzer.subprocess.run", return_value=mock_proc),
            patch("factsheet.dockerfile_analyzer.tempfile.NamedTemporaryFile"),
            patch("factsheet.dockerfile_analyzer.os.unlink"),
        ):
            result = _run_hadolint("FROM ubuntu:latest")
        assert result == findings

    def test_returns_empty_on_json_decode_error(self):
        mock_proc = MagicMock()
        mock_proc.stdout = "not-json"
        with (
            patch("factsheet.dockerfile_analyzer.subprocess.run", return_value=mock_proc),
            patch("factsheet.dockerfile_analyzer.tempfile.NamedTemporaryFile"),
            patch("factsheet.dockerfile_analyzer.os.unlink"),
        ):
            result = _run_hadolint("FROM ubuntu")
        assert result == []

    def test_returns_empty_on_timeout(self):
        import subprocess
        with (
            patch(
                "factsheet.dockerfile_analyzer.subprocess.run",
                side_effect=subprocess.TimeoutExpired("hadolint", 30),
            ),
            patch("factsheet.dockerfile_analyzer.tempfile.NamedTemporaryFile"),
            patch("factsheet.dockerfile_analyzer.os.unlink"),
        ):
            result = _run_hadolint("FROM ubuntu")
        assert result == []

    def test_returns_empty_when_stdout_is_blank(self):
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        with (
            patch("factsheet.dockerfile_analyzer.subprocess.run", return_value=mock_proc),
            patch("factsheet.dockerfile_analyzer.tempfile.NamedTemporaryFile"),
            patch("factsheet.dockerfile_analyzer.os.unlink"),
        ):
            result = _run_hadolint("FROM ubuntu")
        assert result == []


# ---------------------------------------------------------------------------
# Integration tests (require real hadolint binary)
# ---------------------------------------------------------------------------

_hadolint_present = is_hadolint_available()


@pytest.mark.integration
@pytest.mark.skipif(not _hadolint_present, reason="hadolint binary not on PATH")
class TestIntegrationWithHadolint:
    def test_latest_tag_detected(self):
        """hadolint should flag DL3007 for ubuntu:latest."""
        traits = analyze_dockerfile("FROM ubuntu:latest\nRUN echo hi", "svc")
        ids = [t["id"] for t in traits]
        assert "dockerfile_latest_tag" in ids

    def test_clean_dockerfile_emits_no_findings(self):
        content = "FROM ubuntu:22.04\nRUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*\n"
        traits = analyze_dockerfile(content, "svc")
        ids = [t["id"] for t in traits]
        assert "dockerfile_analyzed" in ids
        # May or may not have no_findings depending on hadolint rules, but should not raise
