# ============================================================
# Rolling Baseline Engine
#
# Learns what "normal" traffic looks like by maintaining a
# rolling 30-minute window of per-second request counts.
#
# Key functions:
#  • Per-second buckets - count how many requests arrived each second
#  • Rolling window - only keep the last 30 minutes (1800 buckets)
#  • Per-hour slots - traffic at 3am is different from 3pm, so keep separate windows for each hour of the day
#  • Recalculation - every 60 seconds, recompute mean + stddev from the window
#  • Floor values - prevent false alarms during very quiet periods
# ============================================================

import time           # time.time() for current epoch timestamp
import math           # math.sqrt() for standard deviation
import logging
import threading      # Lock to make baseline thread-safe (multiple threads read it)
from collections import defaultdict, deque   # deque = efficient fixed-size queue
from typing import Optional
from datetime import datetime


logger = logging.getLogger(__name__)


class BaselineEngine:
    """
    Maintains rolling traffic statistics and exposes mean + stddev
    that the detector uses to compute z-scores.

    Thread-safe: the detector thread reads baseline values while the
    monitor thread writes new counts - we use a Lock to coordinate.
    """

    def __init__(self, cfg: dict):
        """
        cfg - the 'baseline' section of config.yaml
        """
        # How many seconds of history to keep (30 min × 60 sec = 1800)
        self.window_seconds   = cfg["window_minutes"] * 60
        self.recalc_interval  = cfg["recalc_interval"]    # seconds between recalcs
        self.min_samples      = cfg["min_samples"]         # min data points before trusting baseline
        self.floor_mean       = cfg["floor_mean"]          # never go below this mean
        self.floor_stddev     = cfg["floor_stddev"]        # never go below this stddev
        self.hourly_slots     = cfg.get("hourly_slots", True)
        self.hourly_min       = cfg.get("hourly_min_samples", 60)

        # Global rolling window
        # deque with maxlen automatically evicts old entries from the left
        # when new ones are added from the right.
        # Each entry is a (timestamp, count) tuple representing one second.
        self._global_window: deque = deque(maxlen=self.window_seconds)

        # Per-hour baselines
        # Dict mapping hour (0–23) to its own rolling window deque.
        # This lets us use the current hour's traffic pattern as the baseline
        # instead of mixing 3am data into a 3pm baseline.
        self._hourly_windows: dict = defaultdict(
            lambda: deque(maxlen=self.window_seconds)
        )

        # Current computed baseline values
        # These are read by the detector thread to compute z-scores.
        self._mean:   float = self.floor_mean
        self._stddev: float = self.floor_stddev

        # Error rate baseline (4xx/5xx requests)
        self._error_mean:   float = self.floor_mean
        self._error_stddev: float = self.floor_stddev

        # Bucket for counting requests in the current second
        # Instead of storing one entry per request (which could be millions),
        # we collapse all requests in a given second into a single count.
        self._current_second: int   = int(time.time())   # epoch second
        self._current_count:  int   = 0                  # requests in current second
        self._current_errors: int   = 0                  # 4xx/5xx in current second

        # Timing for recalculation 
        self._last_recalc: float = time.time()

        # History of recalculations for audit log and dashboard graph
        self.recalc_history: list = []

        # Thread lock
        # multiple threads will read/write baseline values, so we use a Lock to prevent data corruption.
        self._lock = threading.Lock()

        logger.info(
            f"BaselineEngine initialised | window={cfg['window_minutes']}min "
            f"floor_mean={self.floor_mean} floor_stddev={self.floor_stddev}"
        )


    # Public write interface (called by monitor thread)
    def record_request(self, timestamp: float, is_error: bool = False):
        """
        Record one incoming request at the given epoch timestamp.
        Called for EVERY log entry — must be fast (O(1)).

        timestamp - epoch float (seconds since 1970)
        is_error  - True if status code was 4xx or 5xx
        """
        second = int(timestamp)   # truncate to whole second

        with self._lock:
            if second == self._current_second:
                # Same second as before - just increment the count
                self._current_count  += 1
                self._current_errors += (1 if is_error else 0)
            else:
                # New second started, flush the completed second's count
                # into the rolling windows, then start fresh.
                self._flush_current_second()
                self._current_second = second
                self._current_count  = 1
                self._current_errors = (1 if is_error else 0)

            # Check if it's time to recalculate the baseline
            if time.time() - self._last_recalc >= self.recalc_interval: 
                self._recalculate()


    # Public read interface (called by detector thread)
    @property
    def mean(self) -> float:
        """Current effective mean requests/second."""
        with self._lock:
            return self._mean

    @property
    def stddev(self) -> float:
        """Current effective standard deviation of requests/second."""
        with self._lock:
            return self._stddev

    @property
    def error_mean(self) -> float:
        """Current effective mean of error requests/second."""
        with self._lock:
            return self._error_mean

    @property
    def error_stddev(self) -> float:
        """Current effective stddev of error requests/second."""
        with self._lock:
            return self._error_stddev

    def get_snapshot(self) -> dict:
        """
        Return a dict of current baseline state for the dashboard.
        Thread-safe read of all relevant values.
        """
        with self._lock:
            return {
                "mean":         self._mean,
                "stddev":       self._stddev,
                "error_mean":   self._error_mean,
                "error_stddev": self._error_stddev,
                "samples":      len(self._global_window),
                "window_max":   self.window_seconds,
                "last_recalc":  self._last_recalc,
                "recalc_history": list(self.recalc_history[-10:]),  # last 10
            }


    # Private methods
    def _flush_current_second(self):
        """
        Move the completed second's count from the accumulator
        into the rolling window deques.

        Must be called with self._lock already held.
        """
        entry = (self._current_second, self._current_count, self._current_errors)

        # Add to global window - deque automatically evicts oldest if full
        self._global_window.append(entry)

        # Add to the appropriate per-hour slot
        if self.hourly_slots:
            hour = datetime.fromtimestamp(self._current_second).hour
            self._hourly_windows[hour].append(entry)

    def _recalculate(self):
        """
        Recompute mean and stddev from the rolling window.
        Called every `recalc_interval` seconds (while lock is held).

        Algorithm:
          1. Try to use the current hour's window (more relevant)
          2. Fall back to global window if not enough hourly data
          3. Apply floor values so we never compute nonsensical stats
        """
        self._last_recalc = time.time()

        # Decide which window to use
        window = self._pick_window()

        if len(window) < self.min_samples:
            # Not enough data yet — keep using floor values
            logger.debug(f"Baseline: not enough samples ({len(window)} < {self.min_samples}), keeping floor values")
            return

        # Extract just the request counts (index 1 of each tuple)
        counts       = [entry[1] for entry in window]
        error_counts = [entry[2] for entry in window]

        # Compute mean and stddev for request counts
        self._mean,   self._stddev   = self._compute_stats(counts, self.floor_mean, self.floor_stddev)
        self._error_mean, self._error_stddev = self._compute_stats(error_counts, self.floor_mean, self.floor_stddev)

        # Record this recalculation for the audit log and dashboard graph
        record = {
            "time":         datetime.utcnow().isoformat(),
            "mean":         round(self._mean, 4),
            "stddev":       round(self._stddev, 4),
            "error_mean":   round(self._error_mean, 4),
            "samples":      len(window),
            "hour_slot":    datetime.utcnow().hour,
        }
        self.recalc_history.append(record)

        # Keep recalc_history bounded to prevent unbounded memory growth over time (last 1440 entries = 24h at 1/min)
        if len(self.recalc_history) > 1440:
            self.recalc_history = self.recalc_history[-1440:]

        logger.info(
            f"Baseline recalculated | mean={self._mean:.3f} "
            f"stddev={self._stddev:.3f} samples={len(window)}"
        )

    def _pick_window(self) -> deque:
        """
        Choose the best window to compute baseline from.
        Prefer current hour's data if it has enough samples,
        otherwise fall back to the global 30-minute window.
        """
        if not self.hourly_slots:
            return self._global_window

        current_hour = datetime.utcnow().hour
        hourly = self._hourly_windows.get(current_hour)

        # Use hourly slot if it has enough data
        if hourly and len(hourly) >= self.hourly_min:
            return hourly

        # Fall back to global window
        return self._global_window

    @staticmethod
    def _compute_stats(values: list, floor_mean: float, floor_stddev: float):
        """
        Compute mean and population standard deviation from a list of numbers.
        Apply floor values to prevent false alarms during quiet periods.

        Returns (mean, stddev) both >= their respective floor values.
        """
        if not values:
            return floor_mean, floor_stddev

        n = len(values)
        mean = sum(values) / n                        # arithmetic mean

        # Population stddev
        variance = sum((x - mean) ** 2 for x in values) / n
        stddev   = math.sqrt(variance)

        # Apply floors — prevent near-zero values that cause z-score explosions
        mean   = max(mean,   floor_mean)
        stddev = max(stddev, floor_stddev)

        return round(mean, 4), round(stddev, 4)