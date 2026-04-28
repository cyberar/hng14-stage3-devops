import json
import time           # time.sleep() so we don't busy-spin when log is idle
import os             # os.stat() to detect log rotation (file replaced/truncated)
import logging        # Python's built-in logger for internal daemon messages
from dataclasses import dataclass   # clean data container for parsed log lines
from typing import Callable, Optional
from datetime import datetime


# initialize logger for this module
logger = logging.getLogger(__name__)


# ── Data structure for a single parsed log line ──────────────
@dataclass
class LogEntry:
    """
    Represents one HTTP request parsed from a Nginx JSON log line.
    All fields map directly to what Nginx writes in its JSON format.
    """
    source_ip:     str           # client IP (real IP from X-Forwarded-For)
    timestamp:     datetime      # when the request arrived
    method:        str           # HTTP method: GET, POST, DELETE, etc.
    path:          str           # URL path e.g. /index.php/apps/files
    status:        int           # HTTP response code: 200, 404, 500, etc.
    response_size: int           # response body size in bytes
    raw:           str           # the original unparsed JSON string (for debugging)


class LogMonitor:
    """
    Tails a file in real time, parses each new JSON line, and calls
    a callback function with each LogEntry.

    """

    # Initialize the monitor with the log file path and polling interval.
    def __init__(self, log_path: str, poll_interval: float = 0.1):
        """
        log_path      — path to the Nginx JSON access log
        poll_interval — how often (seconds) to check for new lines when idle
        
        """
        self.log_path      = log_path
        self.poll_interval = poll_interval

        self._inode = int | None
        self._file = None
        self.lines_parsed = 0
        self.lines_failed = 0
        
        
    # Public interface
    def tail(self, callback: Callable[[LogEntry], None]):
        """
        Blocking loop. For every new log line:
          1. Parse it into a LogEntry
          2. Call callback(entry)

        This runs forever (until the process is killed or an exception
        propagates).

        callback — a function that accepts a single LogEntry argument.

        """
        logger.info(f"Starting log monitor on: {self.log_path}")

        # Wait for the log file to exist before trying to open it.
        self._wait_for_file()

        # Open the file and seek to the END so we don't replay old history.
        self._open_file(seek_end=True)

        while True: # read new lines until the process is killed
            try:
                line = self._file.readline()   # read one line (non-blocking when at EOF)

                if line:
                    # We got a new line, try to parse it
                    entry = self._parse_line(line.strip())
                    if entry:
                        self.lines_parsed += 1 # count successfully parsed lines
                        callback(entry)        # hand off to detection logic
                    else:
                        self.lines_failed += 1 # count lines that failed to parse
                else:
                    # No new data — check if the file was rotated, then sleep
                    if self._was_rotated():
                        logger.info("Log rotation detected — reopening file from start")
                        self._open_file(seek_end=False)   # read from beginning of new file
                    else:
                        time.sleep(self.poll_interval)    # nothing new, wait briefly

            except Exception as e:
                # Log the error but keep running
                logger.error(f"Error reading log: {e}")
                time.sleep(1)   # brief pause before retrying


    # Internal helper methods (not part of the public interface)
    def _wait_for_file(self):
        """
        Block until the log file exists.
        This handles the race condition at startup where Nginx might
        not have created the log file yet.
        
        """
        while not os.path.exists(self.log_path): # wait for the file to appear
            logger.warning(f"Waiting for log file: {self.log_path}")
            time.sleep(2)   # check every 2 seconds
        logger.info(f"Log file found: {self.log_path}")

    def _open_file(self, seek_end: bool = False):
        """
        Open (or reopen) the log file.
        seek_end=True  -> jump to the end (normal startup behaviour)
        seek_end=False -> read from the beginning (after log rotation)
        
        """
        # Close any existing file handle cleanly
        if self._file:
            try:
                self._file.close()
            except Exception:
                pass

        # Open in text mode — Nginx writes UTF-8 text
        self._file = open(self.log_path, "r", encoding="utf-8", errors="replace")

        if seek_end:
            self._file.seek(0, 2)   # move to end of file so we only read new lines

        # Record the inode so we can detect rotation later
        self._inode = os.stat(self.log_path).st_ino # unique file identifier on disk
        logger.debug(f"Opened log file (inode={self._inode}, seek_end={seek_end})")

    def _was_rotated(self) -> bool:
        """
        Check if the log file has been rotated (replaced or truncated).

        Rotation detection uses two signals:
        1. Inode change — the file on disk is a different file (logrotate renamed + created new)
        2. File shrinkage — the file got smaller (truncated)

        If either is true, we need to reopen.
        """
        try:
            stat = os.stat(self.log_path) # get current file stats
        except FileNotFoundError:
            return True   # file disappeared

        # Check inode: if it changed, this is a new file
        if stat.st_ino != self._inode:
            return True

        # Check if current position is past end of file (file was truncated)
        current_pos = self._file.tell() # where we are in the file
        if current_pos > stat.st_size:
            return True

        return False

    def _parse_line(self, line: str) -> Optional[LogEntry]:
        """
        Parse a single JSON log line into a LogEntry.

        Expected Nginx JSON format (configured in nginx.conf):
        {
          "source_ip":     "1.2.3.4",
          "timestamp":     "2025-04-25T14:32:01+00:00",
          "method":        "GET",
          "path":          "/index.php/apps/files",
          "status":        200,
          "response_size": 4096
        }

        Returns None if the line is malformed (empty lines, non-JSON, etc.)
        """
        if not line:
            return None   # skip blank lines

        try:
            data = json.loads(line)   # parse JSON into a dict

            # Extract each field, providing defaults if keys are missing
            source_ip = data.get("source_ip", "0.0.0.0")
            method    = data.get("method", "UNKNOWN")
            path      = data.get("path", "/")
            status    = int(data.get("status", 0))
            response_size = int(data.get("response_size", 0))

            # Parse timestamp — Nginx writes ISO 8601 format
            ts_raw = data.get("timestamp", "")
            try:
                # Handle timezone offset formats like "+00:00"
                timestamp = datetime.fromisoformat(ts_raw)
            except (ValueError, TypeError):
                # If timestamp is malformed, use current time as a fallback
                timestamp = datetime.utcnow()

            return LogEntry(
                source_ip     = source_ip,
                timestamp     = timestamp,
                method        = method,
                path          = path,
                status        = status,
                response_size = response_size,
                raw           = line,
            )

        except json.JSONDecodeError:
            # Not valid JSON — Nginx might have written a partial line,
            # or there could be some other non-JSON log output.
            logger.debug(f"Skipping non-JSON line: {line[:80]}")
            return None

        except Exception as e:
            logger.warning(f"Failed to parse log line: {e} | line={line[:80]}")
            return None