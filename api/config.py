"""
config.py — Configuration for the Flask API server.
"""

import os

# Flask runtime settings
FLASK_CONFIG = {
    "HOST": os.getenv("API_HOST", "0.0.0.0"),
    "PORT": int(os.getenv("API_PORT", "5004")),
    "DEBUG": os.getenv("FLASK_DEBUG", "false").lower() == "true",
    "JSONIFY_PRETTYPRINT_REGULAR": True,
}

# Logging
LOGGING_CONFIG = {
    "LEVEL": os.getenv("LOG_LEVEL", "INFO"),
    "ENABLE_REQUEST_LOGGING": os.getenv("ENABLE_REQUEST_LOGGING", "true").lower() == "true",
}

# Data directory — override via DATA_DIR environment variable
DATA_DIR: str = os.getenv(
    "DATA_DIR",
    os.path.join(os.path.dirname(__file__), "..", "data"),
)
