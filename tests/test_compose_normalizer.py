"""Tests for compose_normalizer.py."""

import pytest
from factsheet.compose_normalizer import normalize_compose


# ---------------------------------------------------------------------------
# cap_add / cap_drop normalisation
# ---------------------------------------------------------------------------

class TestCapabilities:
    def test_cap_add_strips_cap_prefix(self):
        compose = {"services": {"svc": {"cap_add": ["CAP_SYS_PTRACE"]}}}
        result = normalize_compose(compose)
        assert result["services"]["svc"]["cap_add"] == ["SYS_PTRACE"]

    def test_cap_add_keeps_bare_name(self):
        compose = {"services": {"svc": {"cap_add": ["sys_ptrace"]}}}
        result = normalize_compose(compose)
        assert result["services"]["svc"]["cap_add"] == ["SYS_PTRACE"]

    def test_cap_add_ALL_preserved(self):
        compose = {"services": {"svc": {"cap_add": ["ALL"]}}}
        result = normalize_compose(compose)
        assert result["services"]["svc"]["cap_add"] == ["ALL"]

    def test_cap_drop_strips_cap_prefix(self):
        compose = {"services": {"svc": {"cap_drop": ["CAP_NET_RAW"]}}}
        result = normalize_compose(compose)
        assert result["services"]["svc"]["cap_drop"] == ["NET_RAW"]

    def test_cap_drop_all_lowercase_preserved(self):
        compose = {"services": {"svc": {"cap_drop": ["all"]}}}
        result = normalize_compose(compose)
        assert result["services"]["svc"]["cap_drop"] == ["ALL"]


# ---------------------------------------------------------------------------
# Ports normalisation
# ---------------------------------------------------------------------------

class TestPorts:
    def test_short_syntax_host_container(self):
        compose = {"services": {"svc": {"ports": ["8080:80"]}}}
        result = normalize_compose(compose)
        port = result["services"]["svc"]["ports"][0]
        assert port["target"] == 80
        assert port["published"] == "8080"
        assert port["protocol"] == "tcp"

    def test_short_syntax_no_host(self):
        compose = {"services": {"svc": {"ports": ["80"]}}}
        result = normalize_compose(compose)
        port = result["services"]["svc"]["ports"][0]
        assert port["target"] == 80
        assert port["published"] is None

    def test_short_syntax_with_ip(self):
        compose = {"services": {"svc": {"ports": ["0.0.0.0:3000:3000"]}}}
        result = normalize_compose(compose)
        port = result["services"]["svc"]["ports"][0]
        assert port["target"] == 3000
        assert port["published"] == "3000"

    def test_short_syntax_with_protocol(self):
        compose = {"services": {"svc": {"ports": ["53:53/udp"]}}}
        result = normalize_compose(compose)
        port = result["services"]["svc"]["ports"][0]
        assert port["protocol"] == "udp"

    def test_long_syntax_dict(self):
        compose = {"services": {"svc": {"ports": [{"target": 80, "published": "8080", "protocol": "tcp"}]}}}
        result = normalize_compose(compose)
        port = result["services"]["svc"]["ports"][0]
        assert port["target"] == 80
        assert port["published"] == "8080"


# ---------------------------------------------------------------------------
# Volumes normalisation
# ---------------------------------------------------------------------------

class TestVolumes:
    def test_short_syntax_host_bind(self):
        compose = {"services": {"svc": {"volumes": ["/var:/host-var"]}}}
        result = normalize_compose(compose)
        vol = result["services"]["svc"]["volumes"][0]
        assert vol["type"] == "bind"
        assert vol["source"] == "/var"
        assert vol["target"] == "/host-var"
        assert vol["read_only"] is False

    def test_short_syntax_read_only(self):
        compose = {"services": {"svc": {"volumes": ["/etc:/host-etc:ro"]}}}
        result = normalize_compose(compose)
        vol = result["services"]["svc"]["volumes"][0]
        assert vol["read_only"] is True

    def test_short_syntax_named_volume(self):
        compose = {"services": {"svc": {"volumes": ["mydata:/data"]}}}
        result = normalize_compose(compose)
        vol = result["services"]["svc"]["volumes"][0]
        assert vol["type"] == "volume"
        assert vol["source"] == "mydata"

    def test_long_syntax_bind(self):
        compose = {"services": {"svc": {"volumes": [
            {"type": "bind", "source": "/tmp", "target": "/tmp", "read_only": True}
        ]}}}
        result = normalize_compose(compose)
        vol = result["services"]["svc"]["volumes"][0]
        assert vol["type"] == "bind"
        assert vol["read_only"] is True


# ---------------------------------------------------------------------------
# Networks normalisation
# ---------------------------------------------------------------------------

class TestNetworks:
    def test_service_networks_list_to_dict(self):
        compose = {"services": {"svc": {"networks": ["net1", "net2"]}}}
        result = normalize_compose(compose)
        nets = result["services"]["svc"]["networks"]
        assert isinstance(nets, dict)
        assert "net1" in nets
        assert "net2" in nets

    def test_service_networks_dict_preserved(self):
        compose = {"services": {"svc": {"networks": {"net1": {"aliases": ["alias1"]}}}}}
        result = normalize_compose(compose)
        nets = result["services"]["svc"]["networks"]
        assert nets["net1"]["aliases"] == ["alias1"]

    def test_top_level_networks_list_to_dict(self):
        compose = {"services": {}, "networks": ["net1", "net2"]}
        result = normalize_compose(compose)
        assert isinstance(result["networks"], dict)
        assert "net1" in result["networks"]

    def test_top_level_networks_null_values_become_dict(self):
        compose = {"services": {}, "networks": {"net1": None}}
        result = normalize_compose(compose)
        assert result["networks"]["net1"] == {}


# ---------------------------------------------------------------------------
# Boolean fields
# ---------------------------------------------------------------------------

class TestBooleans:
    def test_privileged_string_coerced(self):
        compose = {"services": {"svc": {"privileged": "true"}}}
        result = normalize_compose(compose)
        assert result["services"]["svc"]["privileged"] is True

    def test_read_only_false_remains_false(self):
        compose = {"services": {"svc": {"read_only": False}}}
        result = normalize_compose(compose)
        assert result["services"]["svc"]["read_only"] is False
