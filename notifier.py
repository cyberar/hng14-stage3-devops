# ============================================================
# Slack Notification Sender
#
# Sends HTTP POST requests to a Slack Incoming Webhook URL.
# Every alert includes: condition, current rate, baseline,
# timestamp, and ban duration where applicable.
# ============================================================

import json          # build the JSON payload
import urllib.request  # make HTTP requests without needing requests library
import urllib.error
import logging
import threading
import time
from datetime import datetime, timezone


logger = logging.getLogger(__name__)


class Notifier:
    """
    Sends structured Slack notifications for ban, unban, and global anomaly events.

    Uses a background queue so slow Slack API calls never block the detection loop.
    If Slack is unavailable, alerts are logged locally and retried once.
    """

    def __init__(self, cfg: dict):
        """
        cfg - full config dict (we use the 'slack' section)
        """
        sc = cfg["slack"]
        self.webhook_url = sc["endpoint"]
        self.enabled     = sc["enabled"]
        self.timeout     = sc.get("timeout_seconds", 5)

        # Fire-and-forget queue 
        import queue
        self._queue  = queue.Queue()
        self._thread = threading.Thread(
            target = self._sender_loop,
            name   = "SlackSenderThread",
            daemon = True,
        )
        self._thread.start()

        # Stats tracking
        self.sent_count:   int = 0
        self.failed_count: int = 0

        logger.info(f"Notifier initialised | enabled={self.enabled}")


    # Public methods (called by main.py, unbanner.py)
    def send_ban_alert(
        self,
        ip:          str,
        condition:   str,
        rate:        float,
        baseline:    float,
        duration:    str,          # e.g. "10min" or "permanent"
        z_score:     float = 0.0,
        is_error_surge: bool = False,
    ):
        """Queue a Slack message for a new IP ban."""
        if not self.enabled:
            return

        emoji = "🚨" if not is_error_surge else "⚠️"
        surge_note = " (error surge)" if is_error_surge else ""

        payload = self._build_payload(
            title  = f"{emoji} IP BANNED{surge_note}",
            color  = "#FF0000",   # red
            fields = [
                ("Banned IP",       ip,                      True),
                ("Condition",       condition,               False),
                ("Current Rate",    f"{rate:.2f} req/s",     True),
                ("Baseline Mean",   f"{baseline:.2f} req/s", True),
                ("Z-Score",         f"{z_score:.2f}",        True),
                ("Ban Duration",    duration,                True),
                ("Timestamp",       self._now(),             False),
            ],
        )
        self._queue.put(payload)

    def send_unban_alert(
        self,
        ip:          str,
        offense:     int,
        duration_min: float,
        condition:   str,
    ):
        """Queue a Slack message for an IP unban."""
        if not self.enabled:
            return

        next_offense = offense + 1   # offense is 0-indexed, show 1-indexed to humans
        payload = self._build_payload(
            title  = "✅ IP UNBANNED",
            color  = "#36A64F",   # green
            fields = [
                ("Unbanned IP",     ip,                       True),
                ("Original Reason", condition,                False),
                ("Offense #",       str(next_offense),        True),
                ("Ban Duration",    f"{duration_min} min",    True),
                ("Timestamp",       self._now(),              False),
            ],
        )
        self._queue.put(payload)

    def send_global_alert(
        self,
        condition:  str,
        rate:       float,
        baseline:   float,
        z_score:    float,
    ):
        """Queue a Slack message for a global traffic anomaly (no IP to ban)."""
        if not self.enabled:
            return

        payload = self._build_payload(
            title  = "🌐 GLOBAL TRAFFIC ANOMALY",
            color  = "#FF6600",   # orange
            fields = [
                ("Condition",       condition,                False),
                ("Global Rate",     f"{rate:.2f} req/s",     True),
                ("Baseline Mean",   f"{baseline:.2f} req/s", True),
                ("Z-Score",         f"{z_score:.2f}",        True),
                ("Action",          "Monitoring — no IP to block", False),
                ("Timestamp",       self._now(),             False),
            ],
        )
        self._queue.put(payload)


    # Background sender thread
    def _sender_loop(self):
        """
        Runs forever in a background thread.
        Pops payloads from the queue and POSTs them to Slack.
        If Slack is temporarily down, waits 5 seconds and retries once.
        """
        import queue
        while True:
            try:
                payload = self._queue.get(timeout=1)   # block up to 1s waiting for work
                self._post(payload)
                self._queue.task_done()
            except queue.Empty:
                continue   # no messages, loop and wait again
            except Exception as e:
                logger.error(f"Slack sender loop error: {e}")

    def _post(self, payload: dict, retry: bool = True):
        """
        HTTP POST the payload to the Slack webhook URL.
        Retries once on failure (network blip, rate limit, etc.)
        """
        body = json.dumps(payload).encode("utf-8")

        # Build the HTTP request manually
        req = urllib.request.Request(
            url     = self.webhook_url,
            data    = body,
            headers = {"Content-Type": "application/json"},
            method  = "POST",
        )

        # Attempt the POST request
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    self.sent_count += 1
                    logger.debug(f"Slack notification sent (total={self.sent_count})")
                else:
                    logger.warning(f"Slack returned non-200: {resp.status}")
                    self.failed_count += 1

        except urllib.error.URLError as e:
            logger.error(f"Slack POST failed: {e}")
            self.failed_count += 1
            if retry:
                # Wait 5 seconds and try one more time
                time.sleep(5)
                self._post(payload, retry=False)

        except Exception as e:
            logger.error(f"Unexpected Slack error: {e}")
            self.failed_count += 1


    # Payload builder
    @staticmethod
    def _build_payload(title: str, color: str, fields: list) -> dict:
        """
        Build a Slack "attachment" message payload.
        """
        return {
            "attachments": [
                {
                    "title":  title,
                    "color":  color,       # left border colour (#RRGGBB)
                    "fields": [
                        {
                            "title": f_title,
                            "value": f_value,
                            "short": f_short,   # True = two fields per row
                        }
                        for f_title, f_value, f_short in fields
                    ],
                    "footer": "HNG Anomaly Detector",
                    "ts":     int(time.time()),   # Unix timestamp shown in Slack
                }
            ]
        }

    @staticmethod
    def _now() -> str:
        """Return current UTC time as a readable string."""
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")