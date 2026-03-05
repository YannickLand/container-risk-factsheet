"""
compose_normalizer.py — Canonicalize Docker Compose multi-syntax fields.

Call normalize_compose(raw_dict) before any trait detection.  The returned
dict has stable, predictable shapes for every field that the extractor
cares about.
"""

from __future__ import annotations
import copy
import re
from typing import Any


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def normalize_compose(compose: dict) -> dict:
    """Return a deep-copy of *compose* with all multi-syntax fields normalised."""
    compose = copy.deepcopy(compose)

    services = compose.get("services") or {}
    top_networks = _normalize_top_level_networks(compose.get("networks") or {})
    top_volumes = _normalize_top_level_volumes(compose.get("volumes") or {})

    for svc_name, svc in services.items():
        if not isinstance(svc, dict):
            services[svc_name] = {}
            continue
        svc = _normalize_service(svc)
        services[svc_name] = svc

    compose["services"] = services
    compose["networks"] = top_networks
    compose["volumes"] = top_volumes
    return compose


# ---------------------------------------------------------------------------
# Service-level normalisation
# ---------------------------------------------------------------------------

def _normalize_service(svc: dict) -> dict:
    """Normalise all known multi-syntax fields inside a single service dict."""
    if "cap_add" in svc:
        svc["cap_add"] = _normalize_capabilities(svc["cap_add"])
    if "cap_drop" in svc:
        svc["cap_drop"] = _normalize_capabilities(svc["cap_drop"])
    if "ports" in svc:
        svc["ports"] = _normalize_ports(svc["ports"])
    if "volumes" in svc:
        svc["volumes"] = _normalize_service_volumes(svc["volumes"])
    if "networks" in svc:
        svc["networks"] = _normalize_service_networks(svc["networks"])
    # Boolean fields — coerce string representations
    for bool_field in ("privileged", "read_only", "tty", "stdin_open"):
        if bool_field in svc:
            svc[bool_field] = _coerce_bool(svc[bool_field])
    return svc


# ---------------------------------------------------------------------------
# Capabilities
# ---------------------------------------------------------------------------

def _normalize_capabilities(caps: Any) -> list[str]:
    """
    Canonicalise cap_add / cap_drop entries.

    Accepts a list of strings in any case with or without the 'CAP_' prefix,
    e.g. 'sys_ptrace', 'CAP_SYS_PTRACE', 'ALL'.
    Returns uppercase entries *without* the 'CAP_' prefix, except 'ALL'.
    """
    if not isinstance(caps, list):
        caps = [caps]
    result = []
    for cap in caps:
        cap = str(cap).strip().upper()
        if cap == "ALL":
            result.append("ALL")
        else:
            # Strip any leading CAP_ prefix to normalise
            cap = re.sub(r'^CAP_', '', cap)
            result.append(cap)
    return result


# ---------------------------------------------------------------------------
# Ports
# ---------------------------------------------------------------------------

def _normalize_ports(ports: Any) -> list[dict]:
    """
    Return a list of port-mapping dicts with keys:
      target (int), published (str|None), protocol (str).

    Input may be:
      • list of strings  "HOST:CONTAINER/proto"  or "CONTAINER/proto"
      • list of dicts    {target, published, protocol}
      • a mapping (treated like a dict)
    """
    if not isinstance(ports, list):
        ports = [ports]

    result = []
    for p in ports:
        if isinstance(p, dict):
            result.append({
                "target": int(p.get("target", 0)) if p.get("target") is not None else None,
                "published": str(p["published"]) if p.get("published") is not None else None,
                "protocol": str(p.get("protocol", "tcp")).lower(),
            })
        else:
            result.append(_parse_port_string(str(p)))
    return result


def _parse_port_string(s: str) -> dict:
    """Parse Compose short-syntax port string into a canonical dict."""
    # Strip any IP prefix like 0.0.0.0:  or 127.0.0.1:
    ip_match = re.match(r'^(\d{1,3}(?:\.\d{1,3}){3}):(.+)$', s)
    if ip_match:
        s = ip_match.group(2)

    # Split off protocol
    protocol = "tcp"
    if "/" in s:
        s, protocol = s.rsplit("/", 1)
        protocol = protocol.lower()

    # Split host : container
    if ":" in s:
        published, target = s.rsplit(":", 1)
        published = published or None
    else:
        published = None
        target = s

    try:
        target_int = int(target)
    except (ValueError, TypeError):
        target_int = target  # keep as-is if non-numeric

    return {"target": target_int, "published": published, "protocol": protocol}


# ---------------------------------------------------------------------------
# Volumes
# ---------------------------------------------------------------------------

def _normalize_service_volumes(vols: Any) -> list[dict]:
    """
    Return a uniform list of volume-mount dicts with keys:
      type ('bind'|'volume'|'tmpfs'), source (str|None), target (str),
      read_only (bool).
    """
    if not isinstance(vols, list):
        vols = [vols]
    result = []
    for v in vols:
        if isinstance(v, dict):
            result.append({
                "type": v.get("type", "volume"),
                "source": v.get("source"),
                "target": v.get("target", ""),
                "read_only": _coerce_bool(v.get("read_only", False)),
            })
        else:
            result.append(_parse_volume_string(str(v)))
    return result


def _parse_volume_string(s: str) -> dict:
    """Parse a Compose short-syntax volume string."""
    read_only = False
    parts = s.split(":")
    if len(parts) == 3:
        source, target, mode = parts
        read_only = (mode.lower() == "ro")
    elif len(parts) == 2:
        source, target = parts
    else:
        # No colon — named volume or relative path
        source = None
        target = s

    # Determine type
    if source and source.startswith("/"):
        vol_type = "bind"
    elif source:
        vol_type = "volume"  # named volume
    else:
        vol_type = "volume"

    return {
        "type": vol_type,
        "source": source if source else None,
        "target": target,
        "read_only": read_only,
    }


def _normalize_top_level_volumes(vols: Any) -> dict:
    """Normalise top-level volumes section into {name: {options}} dict."""
    if isinstance(vols, list):
        return {str(v): {} for v in vols}
    if isinstance(vols, dict):
        result = {}
        for k, v in vols.items():
            result[str(k)] = v if isinstance(v, dict) else {}
        return result
    return {}


# ---------------------------------------------------------------------------
# Networks
# ---------------------------------------------------------------------------

def _normalize_service_networks(nets: Any) -> dict:
    """
    Normalise a service's 'networks' field into {name: {options}} dict.

    Input may be:
      • a list  ["net1", "net2"]  → {net1: {}, net2: {}}
      • a dict  {net1: {aliases: [...]}}  → kept as-is (values coerced)
    """
    if isinstance(nets, list):
        return {str(n): {} for n in nets}
    if isinstance(nets, dict):
        result = {}
        for k, v in nets.items():
            result[str(k)] = v if isinstance(v, dict) else {}
        return result
    return {}


def _normalize_top_level_networks(nets: Any) -> dict:
    """Normalise top-level networks section into {name: {options}} dict."""
    if isinstance(nets, list):
        return {str(n): {} for n in nets}
    if isinstance(nets, dict):
        result = {}
        for k, v in nets.items():
            result[str(k)] = v if isinstance(v, dict) else {}
        return result
    return {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in ("true", "yes", "1", "on")
    return bool(value)
