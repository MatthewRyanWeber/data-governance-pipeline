"""
Generates a self-contained HTML run report after each pipeline execution.

The file can be opened in any browser — no web server required.  Includes
run summary, data quality score, PII masking actions, validation results,
classification level, top changed columns, and governance audit trail.

Layer 3 — imports from pipeline.constants and pipeline.governance_logger.

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py into standalone module.
1.1   2026-06-11   XSS fix: run metadata, quality dimension names, and column
                   names are now html.escape()d before interpolation, matching
                   the existing escaping of audit ledger entries.
"""

import logging
from html import escape
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pandas as pd

    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class HTMLReportGenerator:
    """
    Generates a self-contained HTML run report after each pipeline
    execution.  The file can be opened in any browser — no web server
    required.

    Includes
    --------
    * Run summary (source, destination, row counts, duration)
    * Data quality score and breakdown
    * PII fields detected and masking actions applied
    * Validation results (expectations passed / failed)
    * Classification level
    * Top 5 changed columns (if diff available)
    * Governance audit trail (last 20 entries)

    Quick-start
    -----------
        from pipeline.reporting import HTMLReportGenerator
        reporter = HTMLReportGenerator(gov)
        reporter.generate(
            df        = df_loaded,
            run_meta  = {"source": "data.csv", "destination": "sqlite"},
            quality   = quality_report,
            diff      = diff_report,
        )

    Parameters
    ----------
    gov : GovernanceLogger
    """

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov

    def generate(
        self,
        df: "pd.DataFrame",
        run_meta: dict,
        quality: dict | None = None,
        diff: dict | None = None,
        output_path: str | None = None,
    ) -> str:
        """
        Render and save the HTML report.

        Parameters
        ----------
        df         : pd.DataFrame   The final loaded DataFrame.
        run_meta   : dict           {"source", "destination", "duration_s", ...}
        quality    : dict | None    Output of DataQualityScorer.score()
        diff       : dict | None    Output of DataDiffReporter.compare()
        output_path: str | None     Where to save; defaults to gov log dir.

        Returns
        -------
        str  Path to the saved HTML file.
        """
        ts   = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        path = output_path or str(self.gov.log_dir / f"run_report_{ts}.html")

        score     = quality.get("score", "N/A")       if quality else "N/A"
        q_details = quality.get("dimensions", {})     if quality else {}
        diff_rows = diff.get("rows_changed", 0)       if diff else 0
        diff_add  = diff.get("rows_added", 0)         if diff else 0
        diff_del  = diff.get("rows_deleted", 0)       if diff else 0
        col_changes = diff.get("column_change_counts", {}) if diff else {}
        top_cols  = sorted(col_changes.items(), key=lambda x: x[1], reverse=True)[:5]

        # Audit ledger entries (last 20)
        ledger_entries: list[dict] = []
        if hasattr(self.gov, "ledger_entries"):
            ledger_entries = self.gov.ledger_entries[-20:]

        def _row(k: str, v: str, highlight: bool = False, raw: bool = False) -> str:
            # raw=True is reserved for trusted, code-built HTML (status badge);
            # everything else is escaped to block stored XSS via run metadata
            bg = 'style="background:#fffde7"' if highlight else ""
            value = v if raw else escape(str(v))
            return f"<tr {bg}><td><b>{escape(str(k))}</b></td><td>{value}</td></tr>"

        score_color = (
            "#4caf50" if isinstance(score, (int, float)) and score >= 80
            else "#ff9800" if isinstance(score, (int, float)) and score >= 60
            else "#f44336"
        )

        dim_rows = "".join(
            f"<tr><td>{escape(str(d))}</td><td>{v:.1f}</td></tr>"
            for d, v in q_details.items()
        ) if q_details else "<tr><td colspan=2>Not available</td></tr>"

        col_change_rows = "".join(
            f"<tr><td>{escape(str(c))}</td><td>{escape(str(n))}</td></tr>"
            for c, n in top_cols
        ) if top_cols else "<tr><td colspan=2>No changes detected</td></tr>"

        ledger_html = ""
        for entry in reversed(ledger_entries):
            action  = escape(str(entry.get("action", "")))
            detail  = escape(str(entry.get("detail", ""))[:120])
            ts_str  = escape(str(entry.get("timestamp_utc", ""))[:19])
            ledger_html += f"<tr><td>{ts_str}</td><td>{action}</td><td>{detail}</td></tr>"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Pipeline Run Report — {ts}</title>
<style>
  body{{font-family:system-ui,sans-serif;margin:0;background:#f5f5f5;color:#212121}}
  header{{background:#1565c0;color:#fff;padding:24px 32px}}
  header h1{{margin:0;font-size:1.5em;font-weight:600}}
  header p{{margin:4px 0 0;opacity:.8;font-size:.9em}}
  main{{max-width:1100px;margin:24px auto;padding:0 16px}}
  .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px;margin-bottom:24px}}
  .card{{background:#fff;border-radius:8px;padding:20px;box-shadow:0 1px 4px rgba(0,0,0,.12)}}
  .card h2{{margin:0 0 16px;font-size:1em;text-transform:uppercase;letter-spacing:.05em;color:#555}}
  .score{{font-size:3em;font-weight:700;color:{score_color}}}
  table{{width:100%;border-collapse:collapse;font-size:.9em}}
  th{{background:#e3f2fd;text-align:left;padding:8px 10px;font-weight:600}}
  td{{padding:7px 10px;border-bottom:1px solid #eee}}
  tr:last-child td{{border-bottom:none}}
  .badge{{display:inline-block;padding:2px 8px;border-radius:12px;font-size:.8em;font-weight:600}}
  .success{{background:#e8f5e9;color:#2e7d32}}
  .warning{{background:#fff8e1;color:#e65100}}
  .section{{background:#fff;border-radius:8px;padding:20px;box-shadow:0 1px 4px rgba(0,0,0,.12);margin-bottom:24px}}
  .section h2{{margin:0 0 16px;font-size:1em;text-transform:uppercase;letter-spacing:.05em;color:#555}}
  code{{font-size:.85em;background:#eceff1;padding:1px 5px;border-radius:3px}}
  footer{{text-align:center;padding:24px;color:#999;font-size:.85em}}
</style>
</head>
<body>
<header>
  <h1>Pipeline Run Report</h1>
  <p>Generated {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}</p>
</header>
<main>

<div class="grid">
  <div class="card">
    <h2>Run Summary</h2>
    <table>
      {_row("Source",      run_meta.get("source","—"))}
      {_row("Destination", run_meta.get("destination","—"))}
      {_row("Rows loaded", f"{len(df):,}")}
      {_row("Columns",     str(len(df.columns)))}
      {_row("Duration",    f"{run_meta.get('duration_s','—')}s")}
      {_row("Status",      '<span class="badge success">Success</span>', raw=True)}
    </table>
  </div>
  <div class="card">
    <h2>Data Quality Score</h2>
    <div class="score">{score if score == "N/A" else f"{score:.0f}"}</div>
    <p style="color:#888;margin:4px 0 16px">out of 100</p>
    <table>
      <tr><th>Dimension</th><th>Score</th></tr>
      {dim_rows}
    </table>
  </div>
  <div class="card">
    <h2>Data Changes (vs. last run)</h2>
    <table>
      {_row("Rows added",   f"{diff_add:,}")}
      {_row("Rows deleted", f"{diff_del:,}")}
      {_row("Rows changed", f"{diff_rows:,}", highlight=diff_rows>0)}
    </table>
    <br>
    <b style="font-size:.85em;color:#555">Top changed columns</b>
    <table style="margin-top:8px">
      <tr><th>Column</th><th>Changes</th></tr>
      {col_change_rows}
    </table>
  </div>
</div>

<div class="section">
  <h2>Governance Audit Trail (last 20 entries)</h2>
  <table>
    <tr><th>Timestamp</th><th>Action</th><th>Detail</th></tr>
    {ledger_html if ledger_html else "<tr><td colspan=3>No entries</td></tr>"}
  </table>
</div>

</main>
<footer>data-governance-pipeline &mdash; Generated by HTMLReportGenerator</footer>
</body>
</html>"""

        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(html, encoding="utf-8")
        self.gov.transformation_applied("HTML_REPORT_SAVED", {"path": path})
        logger.info("HTML report saved to %s", path)
        return path
