"""
cli.py — Command-line interface for container-risk-factsheet.

Commands:
  generate-factsheet   Generate a security factsheet from a docker-compose file.
"""

from __future__ import annotations
import json
import sys
import os
import click
import yaml

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resolve_data_dir(data_dir: str | None) -> str:
    if data_dir:
        return data_dir
    # Default: data/ relative to project root (one level above this file)
    return os.path.join(os.path.dirname(__file__), "..", "data")


def _load_overrides(overrides_file: str | None) -> dict[str, str]:
    """Load assumption overrides from a YAML or JSON file."""
    if not overrides_file:
        return {}
    with open(overrides_file, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    return {str(k): str(v) for k, v in raw.items()}


# ---------------------------------------------------------------------------
# CLI root group
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(package_name="container-risk-factsheet")
def cli():
    """Container Risk Factsheet — generate security factsheets from Docker Compose files."""


# ---------------------------------------------------------------------------
# generate-factsheet
# ---------------------------------------------------------------------------

@cli.command("generate-factsheet")
@click.argument("compose_file", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "-o", "--output",
    default=None,
    help="Write JSON output to this file (default: stdout).",
    type=click.Path(dir_okay=False, writable=True),
)
@click.option(
    "--overrides",
    default=None,
    help="YAML/JSON file with manual assumption-state overrides.",
    type=click.Path(exists=True, dir_okay=False),
)
@click.option(
    "--data-dir",
    default=None,
    help="Override the path to the data/ directory containing risk model files.",
    type=click.Path(exists=True, file_okay=False),
)
@click.option(
    "--pretty/--no-pretty",
    default=True,
    help="Pretty-print JSON output (default: True).",
)
def generate_factsheet(
    compose_file: str,
    output: str | None,
    overrides: str | None,
    data_dir: str | None,
    pretty: bool,
) -> None:
    """Generate a security factsheet for each service in COMPOSE_FILE."""
    from factsheet.factsheet_generator import generate_factsheet_from_file

    try:
        overrides_dict = _load_overrides(overrides)
        data_dir = _resolve_data_dir(data_dir)

        factsheet = generate_factsheet_from_file(
            compose_file,
            overrides=overrides_dict,
            data_dir=data_dir,
        )

        indent = 2 if pretty else None
        json_str = json.dumps(factsheet, indent=indent, ensure_ascii=False)

        if output:
            with open(output, "w", encoding="utf-8") as fh:
                fh.write(json_str)
            click.echo(f"Factsheet written to {output}", err=True)
        else:
            click.echo(json_str)

    except FileNotFoundError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)
    except Exception as exc:
        click.echo(f"Error generating factsheet: {exc}", err=True)
        raise


# ---------------------------------------------------------------------------
# extract-traits  (convenience sub-command)
# ---------------------------------------------------------------------------

@cli.command("extract-traits")
@click.argument("compose_file", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--service",
    default=None,
    help="Only show traits for this service name.",
)
@click.option(
    "--pretty/--no-pretty",
    default=True,
    help="Pretty-print JSON output (default: True).",
)
def extract_traits(compose_file: str, service: str | None, pretty: bool) -> None:
    """Extract deployment traits from COMPOSE_FILE and print as JSON."""
    from factsheet.compose_normalizer import normalize_compose
    from factsheet.trait_extractor import extract_all_traits

    with open(compose_file, "r", encoding="utf-8") as fh:
        compose = yaml.safe_load(fh)

    normalised = normalize_compose(compose)
    traits = extract_all_traits(normalised)

    if service:
        if service not in traits:
            click.echo(f"Service '{service}' not found in compose file.", err=True)
            sys.exit(1)
        out = {service: traits[service]}
    else:
        out = traits

    indent = 2 if pretty else None
    click.echo(json.dumps(out, indent=indent, ensure_ascii=False))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cli()
