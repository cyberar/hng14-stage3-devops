# ============================================================
# Live Metrics Web Dashboard
#
# Serves a web page at http://<your-domain>:8080 showing:
#   - Currently banned IPs
#   - Global requests/second
#   - Top 10 source IPs
#   - CPU and memory usage
#   - Current baseline mean/stddev
#   - Daemon uptime
# ============================================================

import time
import os
import logging
import threading
import psutil             # CPU and memory stats from the OS
from datetime import datetime, timezone
from flask import Flask, jsonify, render_template_string

logger = logging.getLogger(__name__)


# HTML template for the dashboard
# The frontend uses fetch() to poll /api/metrics every 3 seconds.
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HNG Anomaly Detector — Live Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg:        #060910;
    --panel:     #0b1120;
    --border:    #1a2744;
    --accent:    #00d4ff;
    --accent2:   #ff3366;
    --green:     #00ff9d;
    --yellow:    #ffd700;
    --text:      #c8d8f0;
    --muted:     #4a6080;
    --font-mono: 'Share Tech Mono', monospace;
    --font-ui:   'Rajdhani', sans-serif;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--font-ui);
    min-height: 100vh;
    overflow-x: hidden;
  }

  /* ── Scan-line overlay ── */
  body::before {
    content: '';
    position: fixed; inset: 0;
    background: repeating-linear-gradient(
      0deg,
      transparent,
      transparent 2px,
      rgba(0,212,255,0.015) 2px,
      rgba(0,212,255,0.015) 4px
    );
    pointer-events: none;
    z-index: 999;
  }

  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 18px 32px;
    border-bottom: 1px solid var(--border);
    background: rgba(0,212,255,0.03);
  }
  .logo {
    font-family: var(--font-mono);
    font-size: 1.1rem;
    color: var(--accent);
    letter-spacing: 0.15em;
  }
  .logo span { color: var(--accent2); }
  .status-pill {
    font-family: var(--font-mono);
    font-size: 0.75rem;
    padding: 4px 14px;
    border-radius: 20px;
    border: 1px solid var(--green);
    color: var(--green);
    animation: pulse 2s infinite;
  }
  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50%       { opacity: 0.5; }
  }

  main {
    padding: 24px 32px;
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    grid-template-rows: auto;
    gap: 16px;
    max-width: 1400px;
    margin: 0 auto;
  }

  /* ── Stat cards ── */
  .card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px 22px;
    position: relative;
    overflow: hidden;
    transition: border-color 0.3s;
  }
  .card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, transparent, var(--accent), transparent);
    opacity: 0.6;
  }
  .card:hover { border-color: var(--accent); }
  .card-label {
    font-size: 0.7rem;
    letter-spacing: 0.15em;
    color: var(--muted);
    text-transform: uppercase;
    margin-bottom: 8px;
  }
  .card-value {
    font-family: var(--font-mono);
    font-size: 2rem;
    color: var(--accent);
    line-height: 1;
  }
  .card-value.danger { color: var(--accent2); }
  .card-value.safe   { color: var(--green); }
  .card-sub {
    font-size: 0.75rem;
    color: var(--muted);
    margin-top: 6px;
    font-family: var(--font-mono);
  }

  /* ── Full-width panels ── */
  .wide { grid-column: span 2; }
  .full { grid-column: span 4; }

  /* ── Table ── */
  .data-table {
    width: 100%;
    border-collapse: collapse;
    font-family: var(--font-mono);
    font-size: 0.82rem;
  }
  .data-table th {
    text-align: left;
    padding: 8px 12px;
    color: var(--muted);
    font-size: 0.68rem;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    border-bottom: 1px solid var(--border);
  }
  .data-table td {
    padding: 9px 12px;
    border-bottom: 1px solid rgba(26,39,68,0.5);
    color: var(--text);
  }
  .data-table tr:last-child td { border-bottom: none; }
  .data-table tr:hover td { background: rgba(0,212,255,0.04); }
  .ip-cell   { color: var(--accent); }
  .ban-cell  { color: var(--accent2); font-weight: 600; }
  .rate-cell { color: var(--yellow); }

  /* ── Progress bar for CPU/MEM ── */
  .bar-wrap { margin-top: 10px; }
  .bar-bg {
    background: var(--border);
    border-radius: 4px;
    height: 6px;
    overflow: hidden;
  }
  .bar-fill {
    height: 100%;
    border-radius: 4px;
    background: linear-gradient(90deg, var(--accent), var(--green));
    transition: width 0.5s ease;
  }
  .bar-fill.hot { background: linear-gradient(90deg, var(--yellow), var(--accent2)); }

  /* ── Baseline graph dots ── */
  #baseline-chart {
    width: 100%; height: 80px;
    display: block;
  }

  /* ── Footer ── */
  footer {
    text-align: center;
    padding: 16px;
    font-size: 0.72rem;
    color: var(--muted);
    font-family: var(--font-mono);
    border-top: 1px solid var(--border);
    margin-top: 16px;
  }
  .uptime-badge {
    display: inline-block;
    background: rgba(0,212,255,0.08);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 2px 10px;
    color: var(--accent);
    margin-left: 8px;
  }
</style>
</head>
<body>

<header>
  <div class="logo">HNG /<span>cloud.ng</span> — ANOMALY DETECTOR</div>
  <div>
    <span id="last-update" style="font-size:0.72rem;color:var(--muted);font-family:var(--font-mono);margin-right:16px;"></span>
    <span class="status-pill" id="status-pill">● LIVE</span>
  </div>
</header>

<main>

  <!-- Row 1: Key stats -->
  <div class="card">
    <div class="card-label">Global Req/s</div>
    <div class="card-value" id="global-rate">—</div>
    <div class="card-sub" id="global-z">z-score: —</div>
  </div>

  <div class="card">
    <div class="card-label">Baseline Mean</div>
    <div class="card-value safe" id="baseline-mean">—</div>
    <div class="card-sub" id="baseline-std">stddev: —</div>
  </div>

  <div class="card">
    <div class="card-label">Banned IPs</div>
    <div class="card-value danger" id="banned-count">0</div>
    <div class="card-sub" id="perm-count">permanent: 0</div>
  </div>

  <div class="card">
    <div class="card-label">Uptime</div>
    <div class="card-value" id="uptime" style="font-size:1.4rem">—</div>
    <div class="card-sub" id="total-requests">requests: —</div>
  </div>

  <!-- Row 2: CPU + Memory -->
  <div class="card wide">
    <div class="card-label">CPU Usage</div>
    <div class="card-value" id="cpu-val">—</div>
    <div class="bar-wrap">
      <div class="bar-bg"><div class="bar-fill" id="cpu-bar" style="width:0%"></div></div>
    </div>
  </div>

  <div class="card wide">
    <div class="card-label">Memory Usage</div>
    <div class="card-value" id="mem-val">—</div>
    <div class="bar-wrap">
      <div class="bar-bg"><div class="bar-fill" id="mem-bar" style="width:0%"></div></div>
    </div>
  </div>

  <!-- Row 3: Top IPs + Active Bans -->
  <div class="card wide">
    <div class="card-label" style="margin-bottom:14px">Top 10 Source IPs (last 60s)</div>
    <table class="data-table">
      <thead><tr><th>#</th><th>IP Address</th><th>Rate (req/s)</th><th>Status</th></tr></thead>
      <tbody id="top-ips-body">
        <tr><td colspan="4" style="color:var(--muted);text-align:center">Loading…</td></tr>
      </tbody>
    </table>
  </div>

  <div class="card wide">
    <div class="card-label" style="margin-bottom:14px">Active Bans</div>
    <table class="data-table">
      <thead><tr><th>IP Address</th><th>Offense</th><th>Duration</th><th>Expires In</th></tr></thead>
      <tbody id="bans-body">
        <tr><td colspan="4" style="color:var(--muted);text-align:center">No active bans</td></tr>
      </tbody>
    </table>
  </div>

  <!-- Row 4: Baseline graph -->
  <div class="card full">
    <div class="card-label" style="margin-bottom:12px">Baseline Mean Over Time (last 10 recalculations)</div>
    <canvas id="baseline-chart"></canvas>
  </div>

</main>

<footer>
  HNG Anomaly Detection Engine &nbsp;|&nbsp; cloud.ng
  <span class="uptime-badge" id="footer-uptime">up 0s</span>
</footer>

<script>
// Data polling
const REFRESH_MS = 3000;   // poll every 3 seconds

async function fetchMetrics() {
  try {
    const res  = await fetch('/api/metrics');
    const data = await res.json();
    update(data);
    document.getElementById('last-update').textContent =
      'updated ' + new Date().toLocaleTimeString();
    document.getElementById('status-pill').textContent = '● LIVE';
    document.getElementById('status-pill').style.borderColor = 'var(--green)';
    document.getElementById('status-pill').style.color = 'var(--green)';
  } catch(e) {
    document.getElementById('status-pill').textContent = '● OFFLINE';
    document.getElementById('status-pill').style.borderColor = 'var(--accent2)';
    document.getElementById('status-pill').style.color = 'var(--accent2)';
  }
}

function update(d) {
  // ── Stats ──
  const globalRate = d.global_rate ?? 0;
  const mean       = d.baseline?.mean ?? 0;
  const stddev     = d.baseline?.stddev ?? 0;
  const zScore     = stddev > 0 ? ((globalRate - mean) / stddev).toFixed(2) : '—';

  document.getElementById('global-rate').textContent = globalRate.toFixed(2);
  document.getElementById('global-z').textContent    = 'z-score: ' + zScore;
  document.getElementById('baseline-mean').textContent = mean.toFixed(3);
  document.getElementById('baseline-std').textContent  = 'stddev: ' + stddev.toFixed(3);

  const bans    = d.active_bans ?? [];
  const permBans= bans.filter(b => b.is_permanent).length;
  document.getElementById('banned-count').textContent = bans.length;
  document.getElementById('perm-count').textContent   = 'permanent: ' + permBans;

  document.getElementById('uptime').textContent          = fmtUptime(d.uptime_seconds ?? 0);
  document.getElementById('total-requests').textContent  = 'requests: ' + (d.total_requests ?? 0).toLocaleString();
  document.getElementById('footer-uptime').textContent   = 'up ' + fmtUptime(d.uptime_seconds ?? 0);

  // ── CPU / Memory ──
  const cpu = d.cpu_percent ?? 0;
  const mem = d.mem_percent ?? 0;
  document.getElementById('cpu-val').textContent = cpu.toFixed(1) + '%';
  document.getElementById('mem-val').textContent = mem.toFixed(1) + '%';
  const cpuBar = document.getElementById('cpu-bar');
  const memBar = document.getElementById('mem-bar');
  cpuBar.style.width = cpu + '%';
  memBar.style.width = mem + '%';
  cpuBar.className = 'bar-fill' + (cpu > 80 ? ' hot' : '');
  memBar.className = 'bar-fill' + (mem > 80 ? ' hot' : '');

  // ── Top IPs ──
  const bannedSet = new Set(bans.map(b => b.ip));
  const topBody   = document.getElementById('top-ips-body');
  if ((d.top_ips ?? []).length === 0) {
    topBody.innerHTML = '<tr><td colspan="4" style="color:var(--muted);text-align:center">No traffic yet</td></tr>';
  } else {
    topBody.innerHTML = (d.top_ips ?? []).map((row, i) => {
      const [ip, rate] = row;
      const status = bannedSet.has(ip)
        ? '<span style="color:var(--accent2)">BANNED</span>'
        : '<span style="color:var(--green)">OK</span>';
      return `<tr>
        <td style="color:var(--muted)">${i+1}</td>
        <td class="ip-cell">${ip}</td>
        <td class="rate-cell">${rate.toFixed(3)}</td>
        <td>${status}</td>
      </tr>`;
    }).join('');
  }

  // ── Active bans ──
  const bansBody = document.getElementById('bans-body');
  if (bans.length === 0) {
    bansBody.innerHTML = '<tr><td colspan="4" style="color:var(--muted);text-align:center">No active bans ✓</td></tr>';
  } else {
    const now = Date.now() / 1000;
    bansBody.innerHTML = bans.map(b => {
      const expiresIn = b.is_permanent
        ? '<span style="color:var(--accent2)">PERMANENT</span>'
        : fmtUptime(Math.max(0, b.expires_at - now));
      const dur = b.is_permanent ? '∞' : b.duration_min + 'm';
      return `<tr>
        <td class="ban-cell">${b.ip}</td>
        <td style="color:var(--yellow)">#${b.offense + 1}</td>
        <td>${dur}</td>
        <td>${expiresIn}</td>
      </tr>`;
    }).join('');
  }

  // ── Baseline chart ──
  drawBaseline(d.baseline?.recalc_history ?? []);
}

// ── Simple canvas sparkline for baseline ─────────────────
function drawBaseline(history) {
  const canvas = document.getElementById('baseline-chart');
  const ctx    = canvas.getContext('2d');
  const W = canvas.offsetWidth; const H = 80;
  canvas.width = W; canvas.height = H;
  ctx.clearRect(0, 0, W, H);

  if (history.length < 2) {
    ctx.fillStyle = '#4a6080';
    ctx.font = '12px Share Tech Mono';
    ctx.fillText('Collecting baseline data…', W/2 - 80, H/2 + 4);
    return;
  }

  const means = history.map(h => h.mean);
  const min   = Math.min(...means) * 0.9;
  const max   = Math.max(...means) * 1.1 || 1;
  const xStep = W / (means.length - 1);

  // Draw grid lines
  ctx.strokeStyle = '#1a2744'; ctx.lineWidth = 1;
  [0.25, 0.5, 0.75].forEach(frac => {
    const y = H - frac * H;
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke();
  });

  // Draw mean line
  ctx.beginPath();
  ctx.strokeStyle = '#00d4ff'; ctx.lineWidth = 2;
  means.forEach((m, i) => {
    const x = i * xStep;
    const y = H - ((m - min) / (max - min)) * (H - 10) - 5;
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.stroke();

  // Draw dots at each data point
  ctx.fillStyle = '#00d4ff';
  means.forEach((m, i) => {
    const x = i * xStep;
    const y = H - ((m - min) / (max - min)) * (H - 10) - 5;
    ctx.beginPath(); ctx.arc(x, y, 3, 0, Math.PI*2); ctx.fill();
    // Label
    ctx.fillStyle = '#4a6080'; ctx.font = '10px Share Tech Mono';
    ctx.fillText(m.toFixed(2), x - 12, y - 8);
    ctx.fillStyle = '#00d4ff';
  });
}

function fmtUptime(secs) {
  secs = Math.floor(secs);
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  if (h > 0) return `${h}h ${m}m ${s}s`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

// ── Start polling ─────────────────────────────────────────
fetchMetrics();
setInterval(fetchMetrics, REFRESH_MS);
</script>
</body>
</html>"""


class Dashboard:
    """
    Flask web server serving the live metrics dashboard.
    Runs in its own daemon thread so it doesn't block the main loop.
    """

    def __init__(self, cfg: dict):
        dc = cfg["dashboard"]
        self.host    = dc["host"]
        self.port    = dc["port"]

        self.app = Flask(__name__)

        # Shared state references
        # These are set by main.py after all components are created.
        self.baseline   = None   # BaselineEngine
        self.detector   = None   # SlidingWindowDetector
        self.blocker    = None   # Blocker
        self.start_time = time.time()

        # Register routes
        self._register_routes()

        logger.info(f"Dashboard initialised | port={self.port}")

    def set_components(self, baseline, detector, blocker):
        """Inject component references after construction."""
        self.baseline = baseline
        self.detector = detector
        self.blocker  = blocker

    def start(self):
        """Start Flask in a background daemon thread."""
        t = threading.Thread(
            target = lambda: self.app.run(
                host    = self.host,
                port    = self.port,
                debug   = False,       # no auto-reloader in production
                use_reloader = False,  # reloader conflicts with threading
            ),
            name   = "DashboardThread",
            daemon = True,
        )
        t.start()
        logger.info(f"Dashboard started at http://{self.host}:{self.port}")

    def _register_routes(self):
        """Define all Flask URL routes."""

        @self.app.route("/")
        def index():
            """Serve the main dashboard HTML page."""
            return render_template_string(DASHBOARD_HTML)

        @self.app.route("/api/metrics")
        def metrics():
            """
            JSON endpoint polled by the dashboard every 3 seconds.
            Returns all live stats in one payload.
            """
            now = time.time()

            # System metrics (CPU, memory)
            cpu_pct = psutil.cpu_percent(interval=None)  # non-blocking (uses cached value)
            mem     = psutil.virtual_memory()

            # Component metrics (safe even if not yet set)
            baseline_snap = self.baseline.get_snapshot() if self.baseline else {}
            global_rate   = self.detector.get_global_rate() if self.detector else 0
            top_ips       = self.detector.get_top_ips(10) if self.detector else []
            total_req     = self.detector.total_requests if self.detector else 0

            # Active bans
            active_bans = []
            if self.blocker:
                for record in self.blocker.get_active_bans():
                    active_bans.append({
                        "ip":          record.ip,
                        "offense":     record.offense,
                        "duration_min": record.duration_min,
                        "expires_at":  record.expires_at,
                        "is_permanent": record.is_permanent,
                        "condition":   record.condition,
                        "banned_at":   record.banned_at,
                    })

            # Build the payload with all metrics
            payload = {
                "global_rate":    global_rate,
                "top_ips":        top_ips,
                "active_bans":    active_bans,
                "baseline":       baseline_snap,
                "cpu_percent":    cpu_pct,
                "mem_percent":    mem.percent,
                "mem_used_mb":    round(mem.used / 1024 / 1024, 1),
                "mem_total_mb":   round(mem.total / 1024 / 1024, 1),
                "uptime_seconds": round(now - self.start_time, 1),
                "total_requests": total_req,
                "timestamp":      datetime.now(timezone.utc).isoformat(),
            }

            return jsonify(payload)

        @self.app.route("/health")
        def health():
            """Simple health check endpoint for load balancers / uptime monitors."""
            return jsonify({"status": "ok", "ts": time.time()})