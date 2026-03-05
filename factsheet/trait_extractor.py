"""
trait_extractor.py — Extract deployment traits from a normalised Docker Compose dict.

Usage::

    from factsheet.compose_normalizer import normalize_compose
    from factsheet.trait_extractor import extract_all_traits

    compose = normalize_compose(yaml.safe_load(open("docker-compose.yml")))
    per_service_traits = extract_all_traits(compose)
    # per_service_traits == {"service_name": [<trait_dict>, ...], ...}

Each trait dict has keys: id, name, source, sourceDetails, type.
"""

from __future__ import annotations
import re
from typing import Any

# ---------------------------------------------------------------------------
# Standard Docker default capabilities (Docker 20.x defaults)
# ---------------------------------------------------------------------------

STANDARD_CAPABILITIES: list[str] = [
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_FSETID",
    "CAP_FOWNER",
    "CAP_MKNOD",
    "CAP_NET_RAW",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SETFCAP",
    "CAP_SETPCAP",
    "CAP_NET_BIND_SERVICE",
    "CAP_SYS_CHROOT",
    "CAP_KILL",
    "CAP_AUDIT_WRITE",
]

# Host paths whose bind-mounts are considered privileged.
# Source path must start with one of these to trigger 'privileged_host_volume'.
_PRIVILEGED_PREFIXES: tuple[str, ...] = (
    "/",        # any absolute path qualifies — we also treat /home, /opt etc.
)

# More targeted: any bind with an absolute source path
def _is_privileged_bind(source: str) -> bool:
    return bool(source) and source.startswith("/")


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

def extract_all_traits(compose: dict) -> dict[str, list[dict]]:
    """
    Return a mapping of *service_name* → list of trait dicts for all services
    in the normalised compose dict.
    """
    services = compose.get("services") or {}
    top_networks = compose.get("networks") or {}
    result: dict[str, list[dict]] = {}
    for svc_name, svc in services.items():
        result[svc_name] = extract_traits(svc_name, svc or {}, top_networks)
    return result


def extract_traits(
    service_name: str,
    service: dict,
    top_level_networks: dict,
) -> list[dict]:
    """
    Extract all deployment traits for a single service.

    *service* must already be normalised via compose_normalizer.
    *top_level_networks* is the top-level networks section of the compose file.
    Returns a list of trait dicts: {id, name, source, sourceDetails, type}.
    """
    traits: list[dict] = []

    # Collect explicitly dropped capabilities to exclude them from defaults
    dropped_caps: set[str] = _collect_dropped_caps(service)

    traits += _extract_cap_add(service_name, service)
    traits += _extract_cap_drop(service_name, service)
    traits += _extract_default_caps(service_name, service, dropped_caps)
    traits += _extract_boolean_traits(service_name, service)
    traits += _extract_pid_traits(service_name, service)
    traits += _extract_network_mode_traits(service_name, service)
    traits += _extract_network_membership_traits(service_name, service, top_level_networks)
    traits += _extract_volume_traits(service_name, service)
    traits += _extract_port_traits(service_name, service)
    traits += _extract_misc_traits(service_name, service)

    return traits


# ---------------------------------------------------------------------------
# Capability extraction
# ---------------------------------------------------------------------------

def _collect_dropped_caps(service: dict) -> set[str]:
    """Return set of dropped capability names (without CAP_ prefix, uppercase)."""
    dropped: set[str] = set()
    for cap in service.get("cap_drop") or []:
        cap = re.sub(r'^CAP_', '', str(cap).strip().upper())
        dropped.add(cap)
    return dropped


def _extract_cap_add(service_name: str, service: dict) -> list[dict]:
    """One trait per explicit cap_add entry."""
    traits: list[dict] = []
    caps = service.get("cap_add") or []
    if not caps:
        return traits

    for cap in caps:
        cap_upper = str(cap).strip().upper()
        # Normalise: strip any CAP_ prefix first, then always add it back for
        # the trait ID and type field.
        bare = re.sub(r'^CAP_', '', cap_upper)
        if bare == "ALL":
            trait_id = "cap_add_ALL"
            cap_type = "ALL"
        else:
            trait_id = f"cap_add_CAP_{bare}"
            cap_type = f"CAP_{bare}"

        traits.append({
            "id": trait_id,
            "name": trait_id,
            "source": "docker-compose",
            "sourceDetails": {
                "services": {service_name: {"cap_add": [bare]}}
            },
            "type": cap_type,
        })
    return traits


def _extract_cap_drop(service_name: str, service: dict) -> list[dict]:
    """One trait per explicit cap_drop entry."""
    traits: list[dict] = []
    caps = service.get("cap_drop") or []
    if not caps:
        return traits

    for cap in caps:
        cap_upper = str(cap).strip().upper()
        bare = re.sub(r'^CAP_', '', cap_upper)
        if bare == "ALL":
            trait_id = "cap_drop_all"
            cap_type = "ALL"
        else:
            trait_id = f"cap_drop_{bare}"
            cap_type = f"CAP_{bare}"

        traits.append({
            "id": trait_id,
            "name": trait_id,
            "source": "docker-compose",
            "sourceDetails": {
                "services": {service_name: {"cap_drop": [bare]}}
            },
            "type": cap_type,
        })
    return traits


def _extract_default_caps(
    service_name: str,
    service: dict,
    dropped_caps: set[str],
) -> list[dict]:
    """
    Add one trait per standard Docker capability unless it was dropped.

    If cap_drop contains ALL, all defaults are suppressed.
    """
    traits: list[dict] = []
    if "ALL" in dropped_caps:
        return traits

    explicit_adds: set[str] = set()
    for cap in service.get("cap_add") or []:
        bare = re.sub(r'^CAP_', '', str(cap).upper())
        explicit_adds.add(bare)

    for full_cap in STANDARD_CAPABILITIES:
        bare = re.sub(r'^CAP_', '', full_cap)
        # Skip if explicitly dropped
        if bare in dropped_caps or f"CAP_{bare}" in dropped_caps:
            continue
        # Skip if already emitted as explicit cap_add (avoid duplicate)
        if bare in explicit_adds:
            continue

        trait_id = f"cap_add_{full_cap}"
        traits.append({
            "id": trait_id,
            "name": trait_id,
            "source": "docker-compose",
            "sourceDetails": {"Docker Default Capability": full_cap},
            "type": "",
        })
    return traits


# ---------------------------------------------------------------------------
# Boolean field traits
# ---------------------------------------------------------------------------

def _extract_boolean_traits(service_name: str, service: dict) -> list[dict]:
    traits: list[dict] = []
    if service.get("privileged"):
        traits.append(_make_trait(
            "privileged_flag", service_name,
            {service_name: {"privileged": True}},
        ))
    if service.get("read_only"):
        traits.append(_make_trait(
            "read_only_filesystem", service_name,
            {service_name: {"read_only": True}},
        ))
    return traits


# ---------------------------------------------------------------------------
# PID / cgroup namespace traits
# ---------------------------------------------------------------------------

def _extract_pid_traits(service_name: str, service: dict) -> list[dict]:
    traits: list[dict] = []
    pid = service.get("pid")
    if pid and str(pid).lower() == "host":
        traits.append(_make_trait(
            "host_pid", service_name,
            {service_name: {"pid": "host"}},
        ))
    cgroup = service.get("cgroup") or service.get("cgroup_parent")
    if cgroup and str(cgroup).lower() == "host":
        traits.append(_make_trait(
            "host_cgroup", service_name,
            {service_name: {"cgroup": "host"}},
        ))
    return traits


# ---------------------------------------------------------------------------
# Network mode traits
# ---------------------------------------------------------------------------

def _extract_network_mode_traits(service_name: str, service: dict) -> list[dict]:
    traits: list[dict] = []
    nm = service.get("network_mode")
    if nm and str(nm).lower() == "host":
        traits.append(_make_trait(
            "host_network", service_name,
            {service_name: {"network_mode": "host"}},
        ))
    return traits


# ---------------------------------------------------------------------------
# Network membership traits (external / internal / layer2)
# ---------------------------------------------------------------------------

def _extract_network_membership_traits(
    service_name: str,
    service: dict,
    top_level_networks: dict,
) -> list[dict]:
    """
    Detect external_network, internal_network, layer2_network.

    Algorithm (mirrors resolveNetworkTraitConsistency in Go):
    1. If the service has no 'networks' and no 'network_mode' → it joins the
       default Docker bridge network which is external.
    2. For each named network the service joins:
       - If the top-level definition has `internal: true` → internal_network
       - If the top-level definition has `external: true` or no definition  →
         external_network
       - If the top-level definition has driver `macvlan` or `ipvlan` →
         layer2_network (in addition to the above when applicable)
    """
    traits: list[dict] = []
    svc_networks: dict = service.get("networks") or {}
    has_network_mode = bool(service.get("network_mode"))

    if not svc_networks and not has_network_mode:
        # Default bridge — external
        traits.append({
            "id": "external_network",
            "name": "external_network",
            "source": "docker-compose",
            "sourceDetails": {
                "services": {
                    service_name: {"networks": ["default"]},
                },
            },
            "type": "",
        })
        return traits

    for net_name in svc_networks:
        net_def = top_level_networks.get(net_name) or {}
        is_internal = _coerce_bool(net_def.get("internal", False))
        is_external = _coerce_bool(net_def.get("external", False))
        driver = str(net_def.get("driver", "")).lower()

        if is_internal:
            traits.append({
                "id": "internal_network",
                "name": "internal_network",
                "source": "docker-compose",
                "sourceDetails": {
                    "services": {service_name: {"networks": [net_name]}},
                },
                "type": "",
            })
        else:
            traits.append({
                "id": "external_network",
                "name": "external_network",
                "source": "docker-compose",
                "sourceDetails": {
                    "services": {service_name: {"networks": [net_name]}},
                },
                "type": "",
            })

        if driver in ("macvlan", "ipvlan"):
            traits.append({
                "id": "layer2_network",
                "name": "layer2_network",
                "source": "docker-compose",
                "sourceDetails": {
                    "services": {service_name: {"networks": [net_name]}},
                },
                "type": "",
            })

    return traits


# ---------------------------------------------------------------------------
# Volume traits
# ---------------------------------------------------------------------------

_SENSITIVE_VOLUME_RE = re.compile(r'^/')  # any absolute host path


def _extract_volume_traits(service_name: str, service: dict) -> list[dict]:
    traits: list[dict] = []
    for vol in service.get("volumes") or []:
        if not isinstance(vol, dict):
            continue
        vol_type = vol.get("type", "volume")
        source = vol.get("source") or ""
        target = vol.get("target") or ""
        read_only = bool(vol.get("read_only", False))

        if vol_type == "bind" and _is_privileged_bind(source):
            access_type = "read_only" if read_only else "read_write"
            bound_info = f"{source}:{target}" + (":ro" if read_only else "")
            traits.append({
                "id": "privileged_host_volume",
                "name": "privileged_host_volume",
                "source": "docker-compose",
                "sourceDetails": {
                    "services": {
                        service_name: {"volumes": [bound_info]},
                    },
                },
                "type": access_type,
            })
        elif vol_type == "volume" and source:
            # Named volume
            traits.append({
                "id": "named_volume",
                "name": "named_volume",
                "source": "docker-compose",
                "sourceDetails": {
                    "services": {service_name: {"volumes": [source]}},
                },
                "type": "",
            })
    return traits


# ---------------------------------------------------------------------------
# Port traits
# ---------------------------------------------------------------------------

def _extract_port_traits(service_name: str, service: dict) -> list[dict]:
    traits: list[dict] = []
    for port in service.get("ports") or []:
        if not isinstance(port, dict):
            continue
        published = port.get("published")
        target = port.get("target")

        # Determine the port number for the host-side
        try:
            host_port = int(published) if published else int(target)
        except (ValueError, TypeError):
            continue

        if host_port < 1024:
            trait_id = "privileged_port"
        else:
            trait_id = "unprivileged_port"

        exposed_str = (
            f"{published}:{target}" if published else str(target)
        )
        traits.append({
            "id": trait_id,
            "name": trait_id,
            "source": "docker-compose",
            "sourceDetails": {
                "services": {service_name: {"ports": [exposed_str]}},
            },
            "type": "",
        })

    # Internal-only exposed ports via 'expose'
    for exposed_port in service.get("expose") or []:
        traits.append({
            "id": "internal_port",
            "name": "internal_port",
            "source": "docker-compose",
            "sourceDetails": {
                "services": {service_name: {"expose": [str(exposed_port)]}},
            },
            "type": "",
        })

    return traits


# ---------------------------------------------------------------------------
# Miscellaneous traits
# ---------------------------------------------------------------------------

def _extract_misc_traits(service_name: str, service: dict) -> list[dict]:
    traits: list[dict] = []

    if service.get("depends_on"):
        dep = service["depends_on"]
        if isinstance(dep, list):
            dep_val = dep
        elif isinstance(dep, dict):
            dep_val = list(dep.keys())
        else:
            dep_val = [str(dep)]
        traits.append(_make_trait(
            "depends_on", service_name,
            {service_name: {"depends_on": dep_val}},
        ))

    user = service.get("user")
    if user is not None:
        user_str = str(user).strip()
        # Non-root: not "root", not "0", not "root:root", not "0:0"
        if user_str not in ("root", "0", "root:root", "0:0", "0:root", "root:0"):
            traits.append(_make_trait(
                "non-root_user", service_name,
                {service_name: {"user": user_str}},
            ))

    return traits


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _make_trait(
    trait_id: str,
    service_name: str,
    detail_value: dict,
    trait_type: str = "",
) -> dict:
    return {
        "id": trait_id,
        "name": trait_id,
        "source": "docker-compose",
        "sourceDetails": {"services": detail_value},
        "type": trait_type,
    }


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in ("true", "yes", "1", "on")
    return bool(value)
