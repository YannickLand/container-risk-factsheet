"""
factsheet_service.py — Business logic bridge between the Flask API and the
factsheet Python package.
"""

from __future__ import annotations
import io
import yaml
from factsheet.factsheet_generator import generate_factsheet
from factsheet.treatment_report import extract_treatments
from api.config import DATA_DIR


def generate_factsheet_from_upload(
    file_content: bytes,
    overrides: dict[str, str] | None = None,
    dockerfiles: list[str] | None = None,
) -> dict:
    """
    Parse *file_content* as YAML and generate a factsheet.

    :param file_content: Raw bytes of a docker-compose YAML file.
    :param overrides: Optional assumption-state overrides.
    :param dockerfiles: Optional list of Dockerfile contents (raw strings),
                        mapped positionally to services.
    :returns: Factsheet dict (keyed by service name).
    :raises ValueError: On YAML parse error.
    """
    try:
        compose = yaml.safe_load(io.BytesIO(file_content))
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML: {exc}") from exc

    if not isinstance(compose, dict) or "services" not in compose:
        raise ValueError(
            "File does not appear to be a valid Docker Compose file "
            "(missing top-level 'services' key)."
        )

    return generate_factsheet(
        compose, overrides=overrides, data_dir=DATA_DIR, dockerfiles=dockerfiles
    )


def generate_treatment_report_from_upload(
    file_content: bytes,
    overrides: dict[str, str] | None = None,
    dockerfiles: list[str] | None = None,
) -> dict:
    """Generate a factsheet and extract its risk treatment report."""
    factsheet = generate_factsheet_from_upload(
        file_content, overrides=overrides, dockerfiles=dockerfiles
    )
    return extract_treatments(factsheet)


def generate_factsheet_from_dict(
    compose: dict,
    overrides: dict[str, str] | None = None,
) -> dict:
    """Generate a factsheet from an already-parsed compose dict."""
    return generate_factsheet(compose, overrides=overrides, data_dir=DATA_DIR)
