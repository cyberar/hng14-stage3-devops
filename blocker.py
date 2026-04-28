# ============================================================
# IP Blocking via iptables
#
# When the detector flags an IP, this module:
#   1. Adds an iptables DROP rule (packets never reach Nginx)
#   2. Records the ban with its expiry time and offense count
#   3. Writes an audit log entry
#
# iptables works at the Linux kernel level — the kernel drops
# matching packets before they ever enter user space.
# Command: iptables -I INPUT -s <ip> -j DROP
#   -I INPUT  = Insert at top of INPUT chain (checked first)
#   -s <ip>   = Match packets FROM this source IP
#   -j DROP   = Silently discard the packet (no response sent)
# ============================================================

import subprocess    # runs iptables as a shell command
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Optional
from datetime import datetime


logger = logging.getLogger(__name__)


@dataclass
class BanRecord:
    """All information about one active or historical ban."""
    ip:           str
    banned_at:    float          # epoch timestamp of ban
    expires_at:   float          # epoch timestamp of expiry (inf = permanent)
    offense:      int            # 0-indexed offense number (0 = first ban)
    duration_min: float          # ban duration in minutes (0 = permanent)
    condition:    str            # what triggered the ban
    rate:         float          # request rate at time of ban
    baseline:     float          # baseline mean at time of ban
    is_permanent: bool = False   # True if this ban never expires


class Blocker:
    """
    Manages the lifecycle of IP bans.
    """

    def __init__(self, cfg: dict, audit_log):
        """
        cfg       — full config dict (we use 'blocking' section)
        audit_log — AuditLogger instance for writing structured log entries
        """
        blockerCfg = cfg["blocking"]

        # Whether to actually run iptables commands.
        # Set enabled=false in config to run in alert-only mode.
        self.enabled = blockerCfg["enabled"]

        # Ban duration schedule (minutes), indexed by offense number.
        # [10, 30, 120] means: 1st offense=10min, 2nd=30min, 3rd=120min
        self.ban_schedule = blockerCfg["ban_schedule_minutes"]

        # after many offense, permanently ban the IP
        self.permanent_after   = blockerCfg["permanent_after"]

        self.audit_log = audit_log

        # Active bans
        # Maps IP address to BanRecord for currently active bans
        self._active_bans: Dict[str, BanRecord] = {}

        # Per-IP offense history
        # Maps IP address to number of times banned
        self._offense_counts: Dict[str, int] = {}

        # Thread lock
        self._lock = threading.Lock()

        logger.info(
            f"Blocker initialised | enabled={self.enabled} "
            f"schedule={self.ban_schedule} permanent_after={self.permanent_after}"
        )


    # Public interface
    def ban(self, ip: str, condition: str, rate: float, baseline: float) -> Optional[BanRecord]:
        """
        Ban an IP address.
          1. Determine ban duration from offense history
          2. Add iptables rule
          3. Record the ban
          4. Write audit log

        Returns the BanRecord, or None if the IP is already banned.
        """
        with self._lock:
            # Don't double-ban an already active ban
            if ip in self._active_bans:
                logger.debug(f"IP {ip} already banned — skipping duplicate ban")
                return None

            # Look up offense count (default 0 for first-time offenders)
            offense = self._offense_counts.get(ip, 0)
            self._offense_counts[ip] = offense + 1   # increment for next time

            # Determine duration from schedule
            now = time.time()
            is_permanent = offense >= self.permanent_after

            if is_permanent:
                duration_min = 0
                expires_at   = float("inf")   # never expires
            else:
                # Clamp offense index to schedule length
                idx          = min(offense, len(self.ban_schedule) - 1)
                duration_min = self.ban_schedule[idx]
                expires_at   = now + duration_min * 60   # convert minutes to seconds

            record = BanRecord(
                ip           = ip,
                banned_at    = now,
                expires_at   = expires_at,
                offense      = offense,
                duration_min = duration_min,
                condition    = condition,
                rate         = rate,
                baseline     = baseline,
                is_permanent = is_permanent,
            )

            # Add iptables rule
            if self.enabled:
                success = self._iptables_drop(ip)
                if not success:
                    logger.error(f"iptables command failed for IP {ip}")
                    # Continue anyway — we still want the audit log entry
            else:
                logger.info(f"[DRY RUN] Would ban IP {ip} (blocking disabled in config)")

            # Record the ban
            self._active_bans[ip] = record

            # Audit log
            duration_str = "permanent" if is_permanent else f"{duration_min}min"
            self.audit_log.write(
                action    = "BAN",
                ip        = ip,
                condition = condition,
                rate      = rate,
                baseline  = baseline,
                duration  = duration_str,
            )

            logger.warning(
                f"BANNED {ip} | offense={offense+1} "
                f"duration={duration_str} condition={condition}"
            )

            return record

    def unban(self, ip: str, reason: str = "ban_expired") -> bool:
        """
        Unban an IP address.
          1. Remove iptables rule
          2. Remove from active bans
          3. Write audit log

        Returns True if the IP was banned and is now unbanned.
        """
        with self._lock:
            if ip not in self._active_bans:
                logger.debug(f"Unban requested for {ip} but it's not in active bans")
                return False

            record = self._active_bans.pop(ip)

            # Remove iptables rule
            if self.enabled:
                self._iptables_remove(ip)
            else:
                logger.info(f"[DRY RUN] Would unban IP {ip}")

            # Audit log
            duration_str = "permanent" if record.is_permanent else f"{record.duration_min}min"
            self.audit_log.write(
                action    = "UNBAN",
                ip        = ip,
                condition = reason,
                rate      = record.rate,
                baseline  = record.baseline,
                duration  = duration_str,
            )

            logger.info(f"UNBANNED {ip} | reason={reason}")
            return True

    def is_banned(self, ip: str) -> bool:
        """Check if an IP is currently banned."""
        with self._lock:
            return ip in self._active_bans

    def get_active_bans(self) -> list:
        """Return list of active BanRecords — called by dashboard."""
        with self._lock:
            return list(self._active_bans.values())

    def get_expired_bans(self) -> list:
        """Return list of IPs whose ban has expired — called by unbanner."""
        now = time.time()
        with self._lock:
            return [
                ip for ip, record in self._active_bans.items()
                if not record.is_permanent and record.expires_at <= now
            ]


    # iptables helpers
    def _iptables_drop(self, ip: str) -> bool:
        """
        Add an iptables DROP rule for the given IP.
        """
        return self._run_iptables(["-I", "INPUT", "-s", ip, "-j", "DROP"])

    def _iptables_remove(self, ip: str) -> bool:
        """
        Remove the DROP rule for the given IP.
        """
        return self._run_iptables(["-D", "INPUT", "-s", ip, "-j", "DROP"])

    @staticmethod
    def _run_iptables(args: list) -> bool:
        """
        Run an iptables command as a subprocess.
        Returns True on success, False on failure.
        """
        cmd = ["iptables"] + args
        try:
            result = subprocess.run(
                cmd,
                capture_output = True,   # capture stdout and stderr
                text           = True,   # decode bytes to string
                timeout        = 5,      # don't hang forever
            )
            if result.returncode != 0:
                logger.error(
                    f"iptables failed: {' '.join(cmd)} "
                    f"stderr={result.stderr.strip()}"
                )
                return False
            return True

        except subprocess.TimeoutExpired:
            logger.error(f"iptables timed out: {' '.join(cmd)}")
            return False

        except FileNotFoundError:
            # iptables not installed or not in PATH
            logger.error("iptables not found — is this running as root on Linux?")
            return False

        except Exception as e:
            logger.error(f"iptables exception: {e}")
            return False