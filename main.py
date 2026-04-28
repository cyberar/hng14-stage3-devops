#!/usr/bin/env python3
# ============================================================
# Daemon Orchestrator
#
# Entry point. It:
#   1. Loads config
#   2. Creates all component instances
#   3. Wires them together (sets callbacks, injects dependencies)
#   4. Starts background threads (dashboard, unbanner, baseline recalc)
#   5. Runs the main log-tailing loop (blocking, runs forever)
#
# Execution model:
#   Thread 1 (main)      — tails log, calls process() per entry (hot path)
#   Thread 2 (dashboard) — Flask web server
#   Thread 3 (unbanner)  — checks for expired bans every 30s
#   Thread 4 (slack)     — drains the Slack notification queue
#   Thread 5 (baseline)  — recalculation is triggered inline in Thread 1
# ============================================================

import logging
import signal
import sys
import time
import threading
import os

# Local modules
from config_loader import load_config
from monitor       import LogMonitor, LogEntry
from baseline      import BaselineEngine
from detector      import SlidingWindowDetector, AnomalyEvent
from blocker       import Blocker
from unbanner      import Unbanner
from notifier      import Notifier
from dashboard     import Dashboard
from audit         import AuditLogger


# ── Configure logging ─────────────────────────────────────────
# Uses Python's standard logging. All modules share this config.
logging.basicConfig(
    level  = logging.INFO,
    format = "%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt = "%Y-%m-%dT%H:%M:%S",
    handlers = [
        logging.StreamHandler(sys.stdout),   # print to console (visible via docker logs)
    ],
)
logger = logging.getLogger("main")


class AnomalyDetectorDaemon:
    """
    Top-level orchestrator. Owns all component instances and the main loop.
    """

    def __init__(self, config_path: str = None):
        logger.info("=" * 60)
        logger.info("  HNG Anomaly Detection Daemon — Starting")
        logger.info("=" * 60)

        # Load configuration
        self.cfg = load_config(config_path)
        logger.info("Configuration loaded successfully")

        # Instantiate all components
        # AuditLogger: writes structured log entries for every ban/unban/recalc
        self.audit = AuditLogger(self.cfg["audit"]["path"])

        # Notifier: sends Slack webhooks (fire-and-forget background thread inside)
        self.notifier = Notifier(self.cfg)

        # BaselineEngine: learns normal traffic patterns from a rolling window
        self.baseline = BaselineEngine(self.cfg["baseline"])

        # SlidingWindowDetector: deque windows + z-score / multiplier checks
        self.detector = SlidingWindowDetector(self.cfg, self.baseline)

        # Blocker: manages iptables rules and ban records
        self.blocker = Blocker(self.cfg, self.audit)

        # Unbanner: background thread that releases expired bans
        self.unbanner = Unbanner(self.blocker, self.notifier)

        # Dashboard: Flask web server for live metrics
        self.dashboard = Dashboard(self.cfg)
        self.dashboard.set_components(self.baseline, self.detector, self.blocker)

        # LogMonitor: tails the Nginx access log line by line
        self.monitor = LogMonitor(
            log_path      = self.cfg["log"]["path"],
            poll_interval = self.cfg["log"]["poll_interval"],
        )

        # Wire the anomaly callback
        # When detector finds an anomaly, it calls this function.
        self.detector.set_anomaly_callback(self._on_anomaly)

        # Graceful shutdown
        # Catch SIGTERM (Docker stop) and SIGINT (Ctrl+C) to shut down cleanly.
        self._shutdown = threading.Event()
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT,  self._handle_signal)

        logger.info("All components initialised")


    # Start the daemon
    def run(self):
        """
        Start all background threads, then enter the main log-tailing loop.
        This method blocks until a shutdown signal is received.
        """
        
        # Start background threads
        # Dashboard web server (Flask in its own thread)
        self.dashboard.start()
        logger.info(
            f"Dashboard live at http://0.0.0.0:{self.cfg['dashboard']['port']}"
        )

        # Unbanner background thread
        self.unbanner.start()

        # Log processing loop
        logger.info("Entering log monitoring loop — tailing Nginx access log")
        try:
            self.monitor.tail(callback=self._process_entry)
        except Exception as e:
            logger.critical(f"Log monitor crashed: {e}", exc_info=True)
        finally:
            self._shutdown_cleanup()


    # Per-request callback (hot path)
    def _process_entry(self, entry: LogEntry):
        """
        Called by LogMonitor for EVERY parsed log line.
        Must be fast — this is called hundreds of times per second under load.

        Steps:
          1. Feed into baseline (records the count for rolling stats)
          2. Feed into detector (updates deque windows, checks for anomalies)
        """
        # Record in baseline (updates per-second bucket and rolling window)
        is_error = entry.status >= 400
        self.baseline.record_request(
            timestamp = entry.timestamp.timestamp(),
            is_error  = is_error,
        )

        # Run sliding window detection (checks if this entry causes an anomaly)
        self.detector.process(entry)


    # Anomaly response callback
    def _on_anomaly(self, event: AnomalyEvent):
        """
        Called by the detector when an anomaly is found.
        This must complete within the 10-second SLA (ban must be active within 10s).

        For per-IP anomalies: ban the IP + send Slack alert
        For global anomalies: send Slack alert only
        """
        logger.warning(
            f"ANOMALY DETECTED | type={event.event_type} ip={event.source_ip} "
            f"rate={event.current_rate:.2f} mean={event.baseline_mean:.2f} "
            f"z={event.z_score:.2f} condition={event.condition}"
        )

        if event.event_type == "per_ip" and event.source_ip:
            # Block the IP
            # ban() returns None if the IP is already banned (avoids double-ban)
            record = self.blocker.ban(
                ip        = event.source_ip,
                condition = event.condition,
                rate      = event.current_rate,
                baseline  = event.baseline_mean,
            )

            if record:
                # Send Slack ban alert
                duration_str = "permanent" if record.is_permanent else f"{record.duration_min}min"
                self.notifier.send_ban_alert(
                    ip             = event.source_ip,
                    condition      = event.condition,
                    rate           = event.current_rate,
                    baseline       = event.baseline_mean,
                    duration       = duration_str,
                    z_score        = event.z_score,
                    is_error_surge = event.is_error_surge,
                )

        elif event.event_type == "global":
            # Global anomaly: alert only, no IP to block
            self.notifier.send_global_alert(
                condition = event.condition,
                rate      = event.current_rate,
                baseline  = event.baseline_mean,
                z_score   = event.z_score,
            )

            # Write to audit log for global events too
            self.audit.write(
                action    = "GLOBAL_ANOMALY",
                ip        = "GLOBAL",
                condition = event.condition,
                rate      = event.current_rate,
                baseline  = event.baseline_mean,
                duration  = "-",
            )


    # Shutdown handling
    def _handle_signal(self, signum, frame):
        """Called when SIGTERM or SIGINT is received."""
        sig_name = signal.Signals(signum).name
        logger.info(f"Received {sig_name} — initiating graceful shutdown")
        self._shutdown.set()
        # Raising SystemExit causes monitor.tail() to exit cleanly
        raise SystemExit(0)

    def _shutdown_cleanup(self):
        """Clean up resources before exiting."""
        logger.info("Shutting down daemon…")
        self.unbanner.stop()
        self.audit.close()
        logger.info("Daemon stopped cleanly")


# Entry point
if __name__ == "__main__":
    # Allow passing a custom config path as CLI argument
    # Usage: python main.py /path/to/config.yaml
    config_path = sys.argv[1] if len(sys.argv) > 1 else None

    daemon = AnomalyDetectorDaemon(config_path)
    daemon.run()