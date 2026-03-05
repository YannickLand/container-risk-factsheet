"""
logger.py — Structured logging helpers for the API server.
"""

import logging
import sys


def setup_logger(name: str = "api") -> logging.Logger:
    """Configure and return a named logger with a sensible format."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger


def log_request_info(logger: logging.Logger, request) -> None:
    logger.info("Request  %s %s  from %s", request.method, request.path, request.remote_addr)


def log_factsheet_generation(
    logger: logging.Logger,
    service_count: int,
    duration_ms: float,
) -> None:
    logger.info(
        "Factsheet generated  services=%d  duration_ms=%.1f",
        service_count,
        duration_ms,
    )
