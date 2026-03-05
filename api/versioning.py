"""
versioning.py — API version constants.
"""

API_VERSION = "v1"
API_VERSION_NUMBER = "1.0.0"


def get_version_info() -> dict:
    return {
        "api_version": API_VERSION,
        "version": API_VERSION_NUMBER,
        "service": "container-risk-factsheet",
    }
