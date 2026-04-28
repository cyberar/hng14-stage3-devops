# ============================================================
# Automatic IP Unban Daemon
#
# Runs in a background thread, waking every 30 seconds to check
# whether any banned IPs have served their time.
#
# Backoff schedule (from config):
#   1st offense → 10 minutes
#   2nd offense → 30 minutes
#   3rd offense → 2 hours
#   4th offense → permanent (never unbanned automatically)
#
# On each unban it fires a Slack notification.
# ============================================================

import time
import logging
import threading
from typing import Callable


logger = logging.getLogger(__name__)


class Unbanner:
    """
    Background daemon thread that periodically checks for expired bans
    and releases them via the Blocker.

    Runs as a daemon thread — it dies automatically when the main process exits,
    so we don't need explicit shutdown logic.
    """

    def __init__(self, blocker, notifier, check_interval: float = 30.0):
        """
        blocker        — Blocker instance (to call .unban() and read expiry times)
        notifier       — Notifier instance (to send Slack alerts on unban)
        check_interval — how often (seconds) to scan for expired bans (default 30s)
                         We check every 30s so the max delay past expiry is 30s.
                         Making it shorter (e.g. 10s) increases accuracy at negligible cost.
        """
        self.blocker        = blocker
        self.notifier       = notifier
        self.check_interval = check_interval

        # Tracking
        self.unbans_performed: int = 0     # total unbans since daemon started

        # Internal thread
        self._thread: threading.Thread = None
        self._stop_event = threading.Event()   # signals the loop to stop cleanly

    def start(self):
        """Start the unbanner background thread."""
        self._stop_event.clear() # ensure the stop event is clear before starting
        self._thread = threading.Thread(
            target  = self._loop,
            name    = "UnbannerThread",
            daemon  = True,    # daemon=True means this thread dies with the main process
        )
        self._thread.start()
        logger.info(f"Unbanner started (check_interval={self.check_interval}s)")

    def stop(self):
        """Signal the unbanner to stop after its current sleep."""
        self._stop_event.set()
        logger.info("Unbanner stop requested")


    # Background loop
    def _loop(self):
        """
        Main loop. Sleeps for `check_interval` seconds, then scans for
        expired bans. Repeats until stopped.
        """
        while not self._stop_event.is_set():
            try:
                self._check_expired()
            except Exception as e:
                # Never let an exception kill this thread — log and continue
                logger.error(f"Unbanner loop error: {e}")

            # Sleep in small increments so we can respond to stop() quickly.
            elapsed = 0.0
            while elapsed < self.check_interval and not self._stop_event.is_set():
                time.sleep(1.0)
                elapsed += 1.0

    def _check_expired(self):
        """
        Get the list of IPs whose ban has expired, unban each one,
        and send a Slack notification.
        """
        # Ask the blocker for IPs past their expiry time
        expired_ips = self.blocker.get_expired_bans()

        if not expired_ips:
            return   # nothing to do

        for ip in expired_ips:
            logger.info(f"Ban expired for {ip} — unbanning")

            # Get ban record before unbanning
            active = self.blocker.get_active_bans()
            record = next((r for r in active if r.ip == ip), None)

            # Remove the iptables rule and audit log the unban
            success = self.blocker.unban(ip, reason="ban_expired")

            if success:
                self.unbans_performed += 1

                # Send Slack notification about the unban
                if record:
                    self.notifier.send_unban_alert(
                        ip           = ip,
                        offense      = record.offense,
                        duration_min = record.duration_min,
                        condition    = record.condition,
                    )