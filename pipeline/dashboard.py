"""
Self-contained HTML dashboard for real-time pipeline status.

Renders a single-page HTML dashboard showing run status, recent runs,
circuit breaker state, and key metrics. Auto-refreshes via JS polling.

Layer 6 — imports from pipeline.circuit_breaker.

Revision history
────────────────
1.0   2026-06-09   Initial release.
"""

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def render_dashboard_html(
    status: dict | None = None,
    recent_runs: list[dict] | None = None,
    circuit_breakers: dict | None = None,
    metrics: dict | None = None,
) -> str:
    """
    Render a self-contained HTML dashboard page.

    All data is server-side rendered into the HTML. The page includes
    JS that polls /health every 10s for circuit breaker updates.
    """
    status = status or {}
    recent_runs = recent_runs or []
    circuit_breakers = circuit_breakers or {}
    metrics = metrics or {}

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    run_id = status.get("run_id", "—")
    run_status = status.get("status", "idle")
    started = status.get("started_at", "—")
    duration = metrics.get("total_duration_sec", "—")
    rows_loaded = metrics.get("rows_output", "—")
    error_rate = metrics.get("error_rate", 0)

    status_color = {"idle": "#757575", "running": "#1565c0",
                    "failed": "#c62828"}.get(run_status, "#2e7d32")

    cb_total = len(circuit_breakers)
    cb_open = sum(1 for b in circuit_breakers.values() if b.get("state") == "open")
    cb_half = sum(1 for b in circuit_breakers.values() if b.get("state") == "half_open")

    runs_html = ""
    for run in recent_runs[:10]:
        r_status = run.get("status", "unknown")
        r_color = {"idle": "#2e7d32", "running": "#1565c0",
                   "failed": "#c62828"}.get(r_status, "#2e7d32")
        runs_html += (
            f"<tr>"
            f"<td>{_esc(run.get('run_id', '—')[:12])}</td>"
            f"<td>{_esc(run.get('source', '—'))}</td>"
            f"<td>{_esc(run.get('destination', '—'))}</td>"
            f"<td><span class='badge' style='background:{r_color}'>{_esc(r_status)}</span></td>"
            f"<td>{_esc(str(run.get('duration', '—')))}</td>"
            f"</tr>"
        )
    if not runs_html:
        runs_html = "<tr><td colspan='5' style='text-align:center;color:#999'>No recent runs</td></tr>"

    cb_html = ""
    for name, info in circuit_breakers.items():
        state = info.get("state", "closed")
        s_color = {"closed": "#2e7d32", "open": "#c62828",
                   "half_open": "#e65100"}.get(state, "#757575")
        cb_html += (
            f"<tr>"
            f"<td>{_esc(name)}</td>"
            f"<td><span class='badge' style='background:{s_color}'>{_esc(state)}</span></td>"
            f"<td>{info.get('failures', 0)}</td>"
            f"<td>{info.get('successes', 0)}</td>"
            f"</tr>"
        )
    if not cb_html:
        cb_html = "<tr><td colspan='4' style='text-align:center;color:#999'>No circuit breakers registered</td></tr>"

    error_pct = f"{error_rate * 100:.1f}%" if isinstance(error_rate, (int, float)) else "—"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Pipeline Dashboard</title>
<style>
*{{box-sizing:border-box}}
body{{font-family:system-ui,sans-serif;margin:0;background:#f5f5f5;color:#212121}}
header{{background:#1565c0;color:#fff;padding:24px 32px;display:flex;justify-content:space-between;align-items:center}}
header h1{{margin:0;font-size:1.4em;font-weight:600}}
header .ts{{font-size:.85em;opacity:.8}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:20px;padding:24px 32px}}
.card{{background:#fff;border-radius:8px;padding:20px;box-shadow:0 1px 4px rgba(0,0,0,.12)}}
.card h2{{margin:0 0 16px;font-size:.85em;text-transform:uppercase;letter-spacing:.05em;color:#555}}
.metric{{font-size:2em;font-weight:700;margin:8px 0}}
.metric-label{{font-size:.8em;color:#999}}
table{{width:100%;border-collapse:collapse;font-size:.9em}}
th{{background:#e3f2fd;text-align:left;padding:8px 10px;font-weight:600}}
td{{padding:8px 10px;border-bottom:1px solid #eee}}
.badge{{display:inline-block;padding:2px 10px;border-radius:12px;color:#fff;font-size:.8em;font-weight:600}}
.full-width{{padding:0 32px 32px}}
@media(prefers-color-scheme:dark){{
  body{{background:#121212;color:#e0e0e0}}
  header{{background:#0d47a1}}
  .card{{background:#1e1e1e;box-shadow:0 1px 4px rgba(255,255,255,.05)}}
  .card h2{{color:#aaa}}
  th{{background:#263238}}
  td{{border-color:#333}}
}}
</style>
</head>
<body>
<header>
  <h1>Data Governance Pipeline</h1>
  <div class="ts">Last updated: {now}</div>
</header>
<div class="grid">
  <div class="card">
    <h2>Current Run</h2>
    <div class="metric" style="color:{status_color}">{_esc(run_status.upper())}</div>
    <div class="metric-label">Run ID: {_esc(str(run_id))}</div>
    <div class="metric-label">Started: {_esc(str(started))}</div>
  </div>
  <div class="card">
    <h2>Throughput</h2>
    <div class="metric">{_esc(str(rows_loaded))}</div>
    <div class="metric-label">rows loaded</div>
    <div class="metric-label">Duration: {_esc(str(duration))}s</div>
  </div>
  <div class="card">
    <h2>Error Rate</h2>
    <div class="metric">{error_pct}</div>
    <div class="metric-label">of input rows</div>
  </div>
  <div class="card">
    <h2>Circuit Breakers</h2>
    <div class="metric">{cb_total}</div>
    <div class="metric-label" id="cb-summary">Open: {cb_open} | Half-Open: {cb_half}</div>
  </div>
</div>
<div class="full-width">
  <div class="card" style="margin-bottom:20px">
    <h2>Recent Runs</h2>
    <table>
      <thead><tr><th>Run ID</th><th>Source</th><th>Destination</th><th>Status</th><th>Duration</th></tr></thead>
      <tbody>{runs_html}</tbody>
    </table>
  </div>
  <div class="card">
    <h2>Circuit Breaker Details</h2>
    <table>
      <thead><tr><th>Name</th><th>State</th><th>Failures</th><th>Successes</th></tr></thead>
      <tbody id="cb-table">{cb_html}</tbody>
    </table>
  </div>
</div>
<script>
setInterval(function(){{
  fetch('/health').then(r=>r.json()).then(d=>{{
    var cb=d.circuit_breakers||{{}};
    var el=document.getElementById('cb-summary');
    if(el)el.textContent='Open: '+(cb.open||0)+' | Half-Open: '+(cb.half_open||0);
  }}).catch(function(){{}});
}},10000);
</script>
</body>
</html>"""


def _esc(text: str) -> str:
    return (text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))
