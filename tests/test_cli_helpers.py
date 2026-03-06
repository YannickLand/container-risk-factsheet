"""
Tests for CLI helper functions in factsheet/cli.py.
"""

from __future__ import annotations
import json
import textwrap

import pytest
import yaml

from factsheet.cli import _load_overrides


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write(tmp_path, name, content):
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return str(p)


# ---------------------------------------------------------------------------
# _load_overrides — no file
# ---------------------------------------------------------------------------

def test_load_overrides_none_returns_empty():
    assert _load_overrides(None) == {}


# ---------------------------------------------------------------------------
# _load_overrides — .conf format
# ---------------------------------------------------------------------------

class TestLoadOverridesConf:
    def test_basic_key_value(self, tmp_path):
        p = _write(tmp_path, "o.conf", "IMG=Satisfied\nNET=Dissatisfied\n")
        assert _load_overrides(p) == {"IMG": "Satisfied", "NET": "Dissatisfied"}

    def test_comments_are_ignored(self, tmp_path):
        content = textwrap.dedent("""
            # This is a comment
            IMG=Satisfied
            # Another comment
            NET=Unknown
        """)
        p = _write(tmp_path, "o.conf", content)
        result = _load_overrides(p)
        assert result == {"IMG": "Satisfied", "NET": "Unknown"}
        assert len(result) == 2

    def test_blank_lines_ignored(self, tmp_path):
        p = _write(tmp_path, "o.conf", "\n\nIMG=Satisfied\n\nNET=Satisfied\n\n")
        assert _load_overrides(p) == {"IMG": "Satisfied", "NET": "Satisfied"}

    def test_whitespace_around_key_and_value(self, tmp_path):
        p = _write(tmp_path, "o.conf", "  IMG  =  Satisfied  \n")
        assert _load_overrides(p) == {"IMG": "Satisfied"}

    def test_ini_extension_treated_same(self, tmp_path):
        p = _write(tmp_path, "o.ini", "RTS=Satisfied\n")
        assert _load_overrides(p) == {"RTS": "Satisfied"}

    def test_example_assumptions_conf(self, tmp_path):
        """Smoke-test that simulates parsing example/assumptions.conf."""
        content = textwrap.dedent("""
            # Security Assumptions Configuration
            IMG=Satisfied
            RTS=Satisfied
            NET=Satisfied
            AUTH=Satisfied
            MON=Satisfied
            CRM=Satisfied
        """)
        p = _write(tmp_path, "assumptions.conf", content)
        result = _load_overrides(p)
        assert result["IMG"] == "Satisfied"
        assert result["CRM"] == "Satisfied"
        assert "SCM" not in result  # not in file — intentionally left Unknown


# ---------------------------------------------------------------------------
# _load_overrides — JSON format
# ---------------------------------------------------------------------------

class TestLoadOverridesJson:
    def test_json_file(self, tmp_path):
        data = {"NET-1": "Satisfied", "IMG": "Dissatisfied"}
        p = _write(tmp_path, "o.json", json.dumps(data))
        assert _load_overrides(p) == {"NET-1": "Satisfied", "IMG": "Dissatisfied"}

    def test_all_values_become_strings(self, tmp_path):
        p = _write(tmp_path, "o.json", '{"NET-1": true}')
        result = _load_overrides(p)
        assert result["NET-1"] == "True"


# ---------------------------------------------------------------------------
# _load_overrides — YAML format
# ---------------------------------------------------------------------------

class TestLoadOverridesYaml:
    def test_yaml_file(self, tmp_path):
        content = "NET-1: Satisfied\nIMG: Dissatisfied\n"
        p = _write(tmp_path, "o.yaml", content)
        assert _load_overrides(p) == {"NET-1": "Satisfied", "IMG": "Dissatisfied"}

    def test_yml_extension(self, tmp_path):
        p = _write(tmp_path, "o.yml", "AUTH: Unknown\n")
        assert _load_overrides(p) == {"AUTH": "Unknown"}

    def test_empty_yaml_returns_empty(self, tmp_path):
        p = _write(tmp_path, "o.yaml", "")
        assert _load_overrides(p) == {}
