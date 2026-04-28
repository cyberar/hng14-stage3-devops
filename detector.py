# ============================================================
# Anomaly Detection Engine
#
# Maintains two deque-based sliding windows:
#   • Per-IP window   — tracks requests per IP in the last 60 seconds
#   • Global window   — tracks ALL requests in the last 60 seconds
#
# On every new request, it checks whether any anomaly condition fires.
# When it does, it calls back into the orchestrator (main.py) to trigger
# blocking and alerting.
# ============================================================

import time
import logging
import threading
from collections import defaultdict, deque   # deque = fast double-ended queue
from typing import Callable, Optional, Dict
from dataclasses import dataclass, field
from monitor import LogEntry
from baseline import BaselineEngine


logger = logging.getLogger(__name__)


# What triggered a detection
@dataclass
class AnomalyEvent:
    """
    Carries all context about a detected anomaly.
    Passed to the blocker and notifier.
    """
    source_ip:    Optional[str]   # None for global anomaly
    event_type:   str             # "per_ip" or "global"
    condition:    str             # human-readable description of what fired
    current_rate: float           # requests/sec at time of detection
    baseline_mean: float          # what "normal" looked like
    baseline_stddev: float        # how much variation we expect
    z_score:      float           # how many stddevs above normal
    timestamp:    float           # epoch time
    is_error_surge: bool = False  # True if triggered by 4xx/5xx spike


class SlidingWindowDetector:
    """
    Uses deque-based sliding windows to compute per-IP and global request rates,
    then checks those rates against the baseline to detect anomalies.

    """

    def __init__(self, cfg: dict, baseline: BaselineEngine):
        """
        cfg      — full config dict (we use 'sliding_window' and 'detection' sections)
        baseline — shared BaselineEngine instance to read mean/stddev from
        """
        detection_cfg = cfg["detection"]
        window_cfg    = cfg["sliding_window"]

        # Window size — how far back we look when computing rates
        self.window_seconds        = window_cfg["window_seconds"]         # per-IP window
        self.global_window_seconds = window_cfg["global_window_seconds"]  # global window

        # Detection thresholds — pulled from config
        self.z_score_threshold     = detection_cfg["z_score_threshold"]    # default 3.0
        self.rate_multiplier       = detection_cfg["rate_multiplier"]      # default 5.0×
        self.error_rate_multiplier = detection_cfg["error_rate_multiplier"]# default 3.0×
        self.tightened_z_score     = detection_cfg["tightened_z_score"]    # default 2.0

        self.baseline = baseline

        # Per-IP request timestamp deques
        # defaultdict auto-creates an empty deque for any new IP.
        self._ip_windows: Dict[str, deque] = defaultdict(deque)

        # Per-IP error timestamp deques
        # Same structure but only tracks 4xx/5xx requests
        self._ip_error_windows: Dict[str, deque] = defaultdict(deque)

        # Global request timestamp deque
        # One big deque tracking all requests regardless of source IP
        self._global_window: deque = deque()

        # Recently flagged IPs
        # Prevents re-alerting the same IP every second during an ongoing attack.
        # Maps IP to the timestamp of when it was last flagged.
        self._recently_flagged: Dict[str, float] = {}
        self._flag_cooldown = 30.0   # don't re-flag the same IP within 30 seconds

        # Thread safety
        self._lock = threading.Lock()

        # Callback for anomaly events
        # Set by main.py after construction.
        # When an anomaly fires, we call: self._on_anomaly(AnomalyEvent)
        self._on_anomaly: Optional[Callable[[AnomalyEvent], None]] = None

        # Stats for dashboard
        self.total_requests: int   = 0
        self.total_anomalies: int  = 0

        logger.info(
            f"SlidingWindowDetector initialised | "
            f"window={self.window_seconds}s z_threshold={self.z_score_threshold} "
            f"rate_mult={self.rate_multiplier}x"
        )

    def set_anomaly_callback(self, callback: Callable[[AnomalyEvent], None]):
        """Register the function to call when an anomaly is detected."""
        self._on_anomaly = callback


    # Main entry point for processing each log entry
    def process(self, entry: LogEntry):
        """
        Process one log entry. Called for every parsed request.

        Steps:
          1. Record the request timestamp in the appropriate deques
          2. Evict stale timestamps (older than window_seconds)
          3. Compute current rates
          4. Check anomaly conditions
          5. Fire callback if anomaly detected
        """
        now = time.time()
        ts  = entry.timestamp.timestamp()    # convert datetime to epoch seconds
        is_error = entry.status >= 400       # 4xx and 5xx are "errors"
        ip  = entry.source_ip

        with self._lock:
            self.total_requests += 1

            # 1. Append to windows
            self._ip_windows[ip].append(ts) # every request contributes to the IP's request rate
            self._global_window.append(ts)
            if is_error:
                self._ip_error_windows[ip].append(ts)

            # 2. Evict stale entries
            ip_cutoff     = now - self.window_seconds
            global_cutoff = now - self.global_window_seconds

            # popleft() removes from the left (oldest end)
            while self._ip_windows[ip] and self._ip_windows[ip][0] < ip_cutoff:
                self._ip_windows[ip].popleft()

            while self._ip_error_windows[ip] and self._ip_error_windows[ip][0] < ip_cutoff:
                self._ip_error_windows[ip].popleft()

            while self._global_window and self._global_window[0] < global_cutoff:
                self._global_window.popleft()

            # 3. Compute rates
            ip_rate     = len(self._ip_windows[ip]) / self.window_seconds
            ip_err_rate = len(self._ip_error_windows[ip]) / self.window_seconds
            global_rate = len(self._global_window) / self.global_window_seconds

            # 4. Read baseline stats
            mean   = self.baseline.mean
            stddev = self.baseline.stddev
            err_mean = self.baseline.error_mean

            # 5. Check anomaly conditions
            event = self._check_ip(ip, ip_rate, ip_err_rate, mean, stddev, err_mean, now)
            if event:
                self.total_anomalies += 1
                if self._on_anomaly:
                    self._on_anomaly(event)
                return   # one alert per request

            event = self._check_global(global_rate, mean, stddev, now)
            if event:
                self.total_anomalies += 1
                if self._on_anomaly:
                    self._on_anomaly(event)


    def get_top_ips(self, n: int = 10) -> list:
        """
        Return the top N most active IPs by current rate.
        Called by the dashboard every few seconds.
        """
        with self._lock:
            now    = time.time()
            cutoff = now - self.window_seconds
            # Compute rates only for IPs that have recent traffic
            rates  = {}
            for ip, dq in self._ip_windows.items():
                # Count only timestamps within the window
                count = sum(1 for t in dq if t >= cutoff)
                if count > 0:
                    rates[ip] = round(count / self.window_seconds, 3)
            # Sort descending by rate and take top N
            return sorted(rates.items(), key=lambda x: x[1], reverse=True)[:n]


    def get_global_rate(self) -> float:
        """Current global request rate (requests/second)."""
        with self._lock:
            now    = time.time()
            cutoff = now - self.global_window_seconds
            count  = sum(1 for t in self._global_window if t >= cutoff)
            return round(count / self.global_window_seconds, 3)
        
        
    # Anomaly checks
    def _check_ip(
        self, ip: str, ip_rate: float, ip_err_rate: float,
        mean: float, stddev: float, err_mean: float, now: float
    ) -> Optional[AnomalyEvent]:
        """
        Check whether a single IP's behaviour is anomalous.
        Returns an AnomalyEvent if anomaly detected, None otherwise.
        """
        # Cooldown check — if this IP was flagged recently, skip to prevent alert fatigue.
        last_flagged = self._recently_flagged.get(ip, 0)
        if now - last_flagged < self._flag_cooldown:
            return None   # still in cooldown period

        # Error surge check — if the IP's error rate is high, tighten the z-score threshold
        error_surge = ip_err_rate > (err_mean * self.error_rate_multiplier)
        effective_z = self.tightened_z_score if error_surge else self.z_score_threshold

        # Z-score check
        # z = (observed - expected) / variation
        z_score = (ip_rate - mean) / stddev if stddev > 0 else 0.0

        if z_score > effective_z:
            self._recently_flagged[ip] = now
            return AnomalyEvent(
                source_ip       = ip,
                event_type      = "per_ip",
                condition       = f"IP z-score={z_score:.2f} > threshold={effective_z}",
                current_rate    = round(ip_rate, 3),
                baseline_mean   = mean,
                baseline_stddev = stddev,
                z_score         = round(z_score, 3),
                timestamp       = now,
                is_error_surge  = error_surge,
            )

        # Rate multiplier check — catches cases where stddev is very small and z-score might not trigger
        if ip_rate > mean * self.rate_multiplier:
            self._recently_flagged[ip] = now
            return AnomalyEvent(
                source_ip       = ip,
                event_type      = "per_ip",
                condition       = f"IP rate={ip_rate:.1f} > {self.rate_multiplier}× mean={mean:.1f}",
                current_rate    = round(ip_rate, 3),
                baseline_mean   = mean,
                baseline_stddev = stddev,
                z_score         = round(z_score, 3),
                timestamp       = now,
                is_error_surge  = error_surge,
            )

        # Error surge alone (without rate spike)
        if error_surge:
            err_z = (ip_err_rate - err_mean) / self.baseline.error_stddev \
                    if self.baseline.error_stddev > 0 else 0.0
            self._recently_flagged[ip] = now
            return AnomalyEvent(
                source_ip       = ip,
                event_type      = "per_ip",
                condition       = f"Error surge: err_rate={ip_err_rate:.3f} > {self.error_rate_multiplier}× e_mean={err_mean:.3f}",
                current_rate    = round(ip_rate, 3),
                baseline_mean   = mean,
                baseline_stddev = stddev,
                z_score         = round(err_z, 3),
                timestamp       = now,
                is_error_surge  = True,
            )

        return None   # no anomaly

    def _check_global(
        self, global_rate: float, mean: float, stddev: float, now: float
    ) -> Optional[AnomalyEvent]:
        """
        Check whether the GLOBAL request rate is anomalous.
        We don't block individual IPs for global anomalies — just alert.
        """
        # Global cooldown key — one global alert at a time
        last_flagged = self._recently_flagged.get("__global__", 0)
        if now - last_flagged < self._flag_cooldown:
            return None

        z_score = (global_rate - mean) / stddev if stddev > 0 else 0.0

        # Global z-score check
        if z_score > self.z_score_threshold:
            self._recently_flagged["__global__"] = now
            return AnomalyEvent(
                source_ip       = None,
                event_type      = "global",
                condition       = f"Global z-score={z_score:.2f} > {self.z_score_threshold}",
                current_rate    = round(global_rate, 3),
                baseline_mean   = mean,
                baseline_stddev = stddev,
                z_score         = round(z_score, 3),
                timestamp       = now,
            )

        # Global rate multiplier check
        if global_rate > mean * self.rate_multiplier:
            self._recently_flagged["__global__"] = now
            return AnomalyEvent(
                source_ip       = None,
                event_type      = "global",
                condition       = f"Global rate={global_rate:.1f} > {self.rate_multiplier}× mean={mean:.1f}",
                current_rate    = round(global_rate, 3),
                baseline_mean   = mean,
                baseline_stddev = stddev,
                z_score         = round(z_score, 3),
                timestamp       = now,
            )

        return None