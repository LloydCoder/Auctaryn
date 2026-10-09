"""
TwinGuard — Structured Logging
JSON-formatted logs for SIEM compatibility.
"""

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path


class JSONFormatter(logging.Formatter):
    """Outputs log records as single-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "module": record.name,
            "message": record.getMessage(),
        }

        if record.exc_info and record.exc_info[0] is not None:
            log_entry["exception"] = self.formatException(record.exc_info)

        # Attach extra fields if present
        for key in ("event", "module_name", "action", "risk_level", "decision", "alert_id"):
            value = getattr(record, key, None)
            if value is not None:
                log_entry[key] = value

        return json.dumps(log_entry, default=str)


def setup_logging(level: str = "INFO", log_file: str | None = None) -> logging.Logger:
    """Configure structured logging for TwinGuard."""

    logger = logging.getLogger("twinguard")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.handlers.clear()

    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(JSONFormatter())
    logger.addHandler(console)

    # File handler (if path provided)
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_path)
        file_handler.setFormatter(JSONFormatter())
        logger.addHandler(file_handler)

    return logger


def get_logger(name: str = "twinguard") -> logging.Logger:
    """Get a named child logger."""
    return logging.getLogger(f"twinguard.{name}")
