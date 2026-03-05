"""Tests for trait_extractor.py."""

import pytest
from factsheet.compose_normalizer import normalize_compose
from factsheet.trait_extractor import extract_traits, extract_all_traits, STANDARD_CAPABILITIES


def _normalize_and_extract(service_config: dict, top_networks: dict = None):
    """Helper: normalise a single-service compose and extract traits."""
    compose = {
        "services": {"svc": service_config},
        "networks": top_networks or {},
    }
    normalised = normalize_compose(compose)
    svc = normalised["services"]["svc"]
    nets = normalised["networks"]
    return extract_traits("svc", svc, nets)


def _trait_ids(traits):
    return {t["id"] for t in traits}


# ---------------------------------------------------------------------------
# Default capabilities
# ---------------------------------------------------------------------------

class TestDefaultCapabilities:
    def test_all_14_defaults_present_with_no_config(self):
        traits = _normalize_and_extract({})
        ids = _trait_ids(traits)
        for cap in STANDARD_CAPABILITIES:
            assert f"cap_add_{cap}" in ids, f"Missing default cap: cap_add_{cap}"

    def test_defaults_suppressed_by_cap_drop_all(self):
        traits = _normalize_and_extract({"cap_drop": ["ALL"]})
        ids = _trait_ids(traits)
        for cap in STANDARD_CAPABILITIES:
            assert f"cap_add_{cap}" not in ids

    def test_single_default_cap_dropped(self):
        traits = _normalize_and_extract({"cap_drop": ["NET_RAW"]})
        ids = _trait_ids(traits)
        assert "cap_add_CAP_NET_RAW" not in ids
        assert "cap_add_CAP_CHOWN" in ids  # others still present

    def test_default_cap_not_duplicated_when_explicitly_added(self):
        # If user explicitly adds a capability that is also a default,
        # we should not get two entries for it.
        traits = _normalize_and_extract({"cap_add": ["CHOWN"]})
        chown_traits = [t for t in traits if t["id"] == "cap_add_CAP_CHOWN"]
        # There should be exactly 1 explicit entry (from cap_add list)
        assert len(chown_traits) == 1
        assert chown_traits[0]["sourceDetails"].get("services") is not None


# ---------------------------------------------------------------------------
# Explicit capabilities
# ---------------------------------------------------------------------------

class TestExplicitCapabilities:
    def test_cap_add_sys_ptrace(self):
        traits = _normalize_and_extract({"cap_add": ["SYS_PTRACE"]})
        ids = _trait_ids(traits)
        assert "cap_add_CAP_SYS_PTRACE" in ids

    def test_cap_add_type_field(self):
        traits = _normalize_and_extract({"cap_add": ["SYS_PTRACE"]})
        t = next(x for x in traits if x["id"] == "cap_add_CAP_SYS_PTRACE")
        assert t["type"] == "CAP_SYS_PTRACE"

    def test_cap_add_source_details_contains_service_name(self):
        traits = _normalize_and_extract({"cap_add": ["SYS_PTRACE"]})
        t = next(x for x in traits if x["id"] == "cap_add_CAP_SYS_PTRACE")
        assert "svc" in t["sourceDetails"]["services"]

    def test_cap_add_ALL(self):
        traits = _normalize_and_extract({"cap_add": ["ALL"]})
        ids = _trait_ids(traits)
        assert "cap_add_ALL" in ids

    def test_cap_drop_one_creates_drop_trait(self):
        traits = _normalize_and_extract({"cap_drop": ["NET_RAW"]})
        ids = _trait_ids(traits)
        assert "cap_drop_NET_RAW" in ids

    def test_cap_drop_all_creates_drop_all_trait(self):
        traits = _normalize_and_extract({"cap_drop": ["ALL"]})
        ids = _trait_ids(traits)
        assert "cap_drop_all" in ids


# ---------------------------------------------------------------------------
# PID namespace
# ---------------------------------------------------------------------------

class TestPidNamespace:
    def test_host_pid_detected(self):
        traits = _normalize_and_extract({"pid": "host"})
        assert "host_pid" in _trait_ids(traits)

    def test_no_host_pid_without_setting(self):
        traits = _normalize_and_extract({})
        assert "host_pid" not in _trait_ids(traits)


# ---------------------------------------------------------------------------
# Network mode
# ---------------------------------------------------------------------------

class TestNetworkMode:
    def test_host_network_mode_detected(self):
        traits = _normalize_and_extract({"network_mode": "host"})
        assert "host_network" in _trait_ids(traits)


# ---------------------------------------------------------------------------
# Boolean traits
# ---------------------------------------------------------------------------

class TestBooleanTraits:
    def test_privileged_flag_detected(self):
        traits = _normalize_and_extract({"privileged": True})
        assert "privileged_flag" in _trait_ids(traits)

    def test_read_only_filesystem_detected(self):
        traits = _normalize_and_extract({"read_only": True})
        assert "read_only_filesystem" in _trait_ids(traits)

    def test_privileged_false_not_detected(self):
        traits = _normalize_and_extract({"privileged": False})
        assert "privileged_flag" not in _trait_ids(traits)


# ---------------------------------------------------------------------------
# Volume traits
# ---------------------------------------------------------------------------

class TestVolumeTraits:
    def test_host_bind_volume_read_write(self):
        traits = _normalize_and_extract({"volumes": ["/var:/host-var"]})
        ids = _trait_ids(traits)
        assert "privileged_host_volume" in ids

    def test_host_bind_type_read_write(self):
        traits = _normalize_and_extract({"volumes": ["/var:/host-var"]})
        t = next(x for x in traits if x["id"] == "privileged_host_volume")
        assert t["type"] == "read_write"

    def test_host_bind_volume_read_only(self):
        traits = _normalize_and_extract({"volumes": ["/etc:/etc:ro"]})
        t = next(x for x in traits if x["id"] == "privileged_host_volume")
        assert t["type"] == "read_only"

    def test_named_volume_detected(self):
        traits = _normalize_and_extract({"volumes": ["mydata:/data"]})
        assert "named_volume" in _trait_ids(traits)

    def test_host_bind_long_syntax(self):
        traits = _normalize_and_extract({"volumes": [
            {"type": "bind", "source": "/tmp", "target": "/tmp", "read_only": False}
        ]})
        assert "privileged_host_volume" in _trait_ids(traits)


# ---------------------------------------------------------------------------
# Port traits
# ---------------------------------------------------------------------------

class TestPortTraits:
    def test_unprivileged_port(self):
        traits = _normalize_and_extract({"ports": ["0.0.0.0:3000:3000"]})
        assert "unprivileged_port" in _trait_ids(traits)

    def test_privileged_port(self):
        traits = _normalize_and_extract({"ports": ["80:80"]})
        assert "privileged_port" in _trait_ids(traits)

    def test_expose_creates_internal_port(self):
        traits = _normalize_and_extract({"expose": ["8080"]})
        assert "internal_port" in _trait_ids(traits)


# ---------------------------------------------------------------------------
# Network membership traits
# ---------------------------------------------------------------------------

class TestNetworkTraits:
    def test_no_network_config_gives_external_network(self):
        traits = _normalize_and_extract({})
        assert "external_network" in _trait_ids(traits)

    def test_external_network_when_top_level_not_internal(self):
        compose = {
            "services": {"svc": {"networks": ["mynet"]}},
            "networks": {"mynet": {"external": True}},
        }
        normalised = normalize_compose(compose)
        traits = extract_traits("svc", normalised["services"]["svc"], normalised["networks"])
        assert "external_network" in _trait_ids(traits)

    def test_internal_network_when_top_level_internal_true(self):
        compose = {
            "services": {"svc": {"networks": ["mynet"]}},
            "networks": {"mynet": {"internal": True}},
        }
        normalised = normalize_compose(compose)
        traits = extract_traits("svc", normalised["services"]["svc"], normalised["networks"])
        assert "internal_network" in _trait_ids(traits)
        assert "external_network" not in _trait_ids(traits)

    def test_layer2_network_detected(self):
        compose = {
            "services": {"svc": {"networks": ["l2net"]}},
            "networks": {"l2net": {"driver": "macvlan"}},
        }
        normalised = normalize_compose(compose)
        traits = extract_traits("svc", normalised["services"]["svc"], normalised["networks"])
        assert "layer2_network" in _trait_ids(traits)


# ---------------------------------------------------------------------------
# Misc traits
# ---------------------------------------------------------------------------

class TestMiscTraits:
    def test_non_root_user(self):
        traits = _normalize_and_extract({"user": "appuser"})
        assert "non-root_user" in _trait_ids(traits)

    def test_root_user_not_detected(self):
        traits = _normalize_and_extract({"user": "root"})
        assert "non-root_user" not in _trait_ids(traits)

    def test_user_0_not_detected(self):
        traits = _normalize_and_extract({"user": "0"})
        assert "non-root_user" not in _trait_ids(traits)

    def test_image_field_does_not_produce_trait(self):
        # container_image_name is not extracted from compose (it's added via init/add-traits)
        traits = _normalize_and_extract({"image": "nginx:latest"})
        assert "container_image_name" not in _trait_ids(traits)

    def test_depends_on_trait(self):
        traits = _normalize_and_extract({"depends_on": ["db"]})
        assert "depends_on" in _trait_ids(traits)


# ---------------------------------------------------------------------------
# Multi-service compose
# ---------------------------------------------------------------------------

class TestMultiService:
    def test_each_service_extracted_independently(self):
        compose = {
            "services": {
                "web": {"pid": "host"},
                "db": {"read_only": True},
            }
        }
        normalised = normalize_compose(compose)
        all_traits = extract_all_traits(normalised)
        web_ids = _trait_ids(all_traits["web"])
        db_ids = _trait_ids(all_traits["db"])
        assert "host_pid" in web_ids
        assert "host_pid" not in db_ids
        assert "read_only_filesystem" in db_ids
        assert "read_only_filesystem" not in web_ids
