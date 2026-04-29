# ============================================================
# Structured Audit Logger
# Writes one line per significant event in a structured format:
#   [timestamp] ACTION ip | condition | rate | baseline | duration
# ============================================================

import os
import logging
import threading
from datetime import datetime, timezone


logger = logging.getLogger(__name__)


class AuditLogger:
    """
    Writes structured audit log entries to a file.
    Thread-safe: ban and baseline events can arrive from different threads.
    """

    def __init__(self, log_path: str):
        """
        log_path — where to write the audit log
        """
        self.log_path = log_path

        # Ensure the directory exists - create it if not
        os.makedirs(os.path.dirname(log_path), exist_ok=True)

        # Thread lock prevents two threads writing the same line simultaneously
        self._lock = threading.Lock()

        # Open in append mode with line buffering and UTF-8 encoding
        self._file = open(log_path, "a", buffering=1, encoding="utf-8")

        logger.info(f"Audit log opened: {log_path}")

    def write(
        self,
        action:    str,           # BAN, UNBAN, BASELINE_RECALC
        ip:        str = "-",     # IP address or "-" for global events
        condition: str = "",      # what triggered the action
        rate:      float = 0.0,   # observed rate at time of event
        baseline:  float = 0.0,   # baseline mean at time of event
        duration:  str = "-",     # ban duration or "-"
        extra:     dict = None,   # optional additional key=value pairs
    ):
        """
        Write one structured audit log line.

        Format:
          [2025-04-25T14:32:01Z] BAN ip=1.2.3.4 | condition=z_score>3.0 | rate=142.30 | baseline=12.10 | duration=10min
          [2025-04-25T14:45:00Z] BASELINE_RECALC ip=- | condition=scheduled | rate=0.00 | baseline=13.20 | duration=-
        """
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Build the core line
        line = (
            f"[{ts}] {action:<16} ip={ip:<20} | "
            f"condition={condition} | "
            f"rate={rate:.2f} | "
            f"baseline={baseline:.2f} | "
            f"duration={duration}"
        )

        # Append any extra key=value pairs (e.g. stddev, z_score)
        if extra:
            extras = " | ".join(f"{k}={v}" for k, v in extra.items())
            line += f" | {extras}"

        with self._lock:
            self._file.write(line + "\n")

        # Also log at INFO level so it appears in the daemon's console output
        logger.info(f"AUDIT: {line}")

    def close(self):
        """Flush and close the audit log file cleanly."""
        with self._lock:
            if self._file and not self._file.closed:
                self._file.flush()
                self._file.close()
                logger.info("Audit log closed")