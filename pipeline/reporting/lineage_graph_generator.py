"""
Reads the GovernanceLogger audit ledger and renders a fully interactive,
self-contained HTML lineage graph — no web server or external files needed.

Features: curved Bezier edges, entrance animation, column nodes with dtype
badges, minimap, stage icons, focus mode, filter toggles, PNG export,
hover tooltips, edge row counts, row-drop indicators, stage durations.

Layer 3 — imports from pipeline.constants and pipeline.governance_logger.

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py into standalone module.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class LineageGraphGenerator:
    """
    Reads the GovernanceLogger audit ledger and renders a fully interactive,
    self-contained HTML lineage graph — no web server or external files needed.

    Features (v2)
    -------------
    * Curved Bezier edges           -- S-curve paths, no overlap
    * Smooth entrance animation     -- nodes flow in left to right on load
    * Improved column nodes         -- readable pill labels + dtype badge
    * Minimap                       -- overview navigator (bottom-right)
    * Stage icons                   -- emoji per transform type
    * Focus mode                    -- click a node to isolate its lineage path
    * Filter toggles                -- show/hide PII / transforms / columns
    * Export to PNG                 -- download button saves graph as image
    * Hover tooltips                -- metadata popup follows cursor
    * Edge row counts               -- rows-in-transit label on each connection
    * Row drop indicators           -- badge on validation / dedup nodes
    * Stage durations               -- elapsed time badge on transform nodes

    Quick-start
    -----------
        from pipeline.reporting import LineageGraphGenerator
        gen  = LineageGraphGenerator(gov)
        path = gen.generate()
        path = gen.generate("out.html")

    Parameters
    ----------
    gov : GovernanceLogger
    """

    # ── Stage icons ───────────────────────────────────────────────────────
    STAGE_ICONS: dict[str, str] = {
        "EXTRACT":         "\U0001f4e5",
        "CLASSIFY":        "\U0001f3f7️",
        "MASK_PII":        "\U0001f512",
        "VALIDATE":        "✅",
        "NULLS":           "\U0001f9f9",
        "DEDUP":           "♻️",
        "TRANSFORM_DONE":  "⚙️",
        "DEFAULT":         "▶",
    }

    # ── dtype -> short label ──────────────────────────────────────────────
    DTYPE_LABELS: dict[str, str] = {
        "int64":              "int",
        "Int64":              "int",
        "float64":            "float",
        "Float64":            "float",
        "bool":               "bool",
        "boolean":            "bool",
        "object":             "str",
        "datetime64[ns]":     "date",
        "datetime64[ns, UTC]":"date",
    }

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov
        self._manual_nodes: list[dict] = []
        self._manual_edges: list[dict] = []

    # ── Programmatic graph-building API ───────────────────────────────────

    def add_node(
        self,
        node_id:  str,
        node_type: str = "transform",
        meta:      dict | None = None,
        label:     str | None = None,
        icon:      str = "",
    ) -> "LineageGraphGenerator":
        """
        Add a node to the manually constructed lineage graph.

        Parameters
        ----------
        node_id   : str   Unique node identifier.
        node_type : str   Node category — e.g. "source", "transform", "destination".
        meta      : dict  Arbitrary metadata shown in the hover tooltip.
        label     : str   Display label (defaults to node_id).
        icon      : str   Emoji icon (optional).

        Returns self for chaining.
        """
        self._manual_nodes.append({
            "id":       node_id,
            "label":    label or node_id,
            "type":     node_type,
            "icon":     icon,
            "meta":     meta or {},
            "rows_out": None,
            "drops":    0,
            "ts":       "",
            "duration_s": None,
        })
        return self

    def add_edge(
        self,
        source:    str,
        target:    str,
        label:     str = "solid",
        row_count: int | None = None,
    ) -> "LineageGraphGenerator":
        """
        Add a directed edge between two nodes.

        Parameters
        ----------
        source    : str   Source node_id.
        target    : str   Target node_id.
        label     : str   Edge style / label (e.g. "TRANSFORM", "solid").
        row_count : int   Optional row count displayed on the edge.

        Returns self for chaining.
        """
        self._manual_edges.append({
            "source":    source,
            "target":    target,
            "style":     label,
            "row_count": row_count,
        })
        return self

    def to_dict(self) -> dict:
        """
        Return the current graph (manual nodes/edges + any ledger-derived
        nodes/edges) as a plain dict.

        Returns
        -------
        dict with keys "nodes" and "edges".
        """
        if self._manual_nodes or self._manual_edges:
            return {
                "nodes": list(self._manual_nodes),
                "edges": list(self._manual_edges),
            }
        nodes, edges = self._build_graph()
        return {"nodes": nodes, "edges": edges}

    # ── Ledger -> graph model ─────────────────────────────────────────────

    def _build_graph(self) -> tuple[list[dict], list[dict]]:
        """
        Walk the ledger entries and produce enriched nodes + edges.

        Returns
        -------
        nodes : list[dict]   {id, label, type, icon, meta, rows_out, drops, duration_s}
        edges : list[dict]   {source, target, style, row_count}
        """
        entries = self.gov.ledger_entries
        nodes: list[dict] = []
        edges: list[dict] = []
        seen_ids: set[str] = set()

        # ── helpers ───────────────────────────────────────────────────────
        def _add_node(nid: str, label: str, ntype: str, meta: dict,
                      icon: str = "", rows_out: int | None = None,
                      drops: int = 0, ts: str = "",
                      duration_s: float | None = None) -> None:
            if nid not in seen_ids:
                nodes.append({
                    "id": nid, "label": label, "type": ntype,
                    "icon": icon, "meta": meta,
                    "rows_out":   rows_out,
                    "drops":      drops,
                    "ts":         ts,
                    "duration_s": duration_s,
                })
                seen_ids.add(nid)

        def _add_edge(src: str, tgt: str, style: str = "solid",
                      row_count: int | None = None) -> None:
            edges.append({"source": src, "target": tgt,
                           "style": style, "row_count": row_count})

        # ── state ─────────────────────────────────────────────────────────
        source_id:         str | None = None
        destination_id:    str | None = None
        pii_fields:        set[str]   = set()
        all_columns:       list[str]  = []
        dtypes:            dict[str, str] = {}
        transform_chain:   list[str]  = []
        last_transform_id: str | None = None
        current_row_count: int | None = None
        stage_timestamps:  dict[str, str] = {}
        total_drops:       int = 0

        def _parse_ts(ts_str: str) -> float:
            """Parse ISO timestamp to float seconds."""
            try:
                return datetime.fromisoformat(
                    ts_str.replace("Z", "+00:00")
                ).timestamp()
            except Exception:
                return 0.0

        for entry in entries:
            action    = entry.get("action", "")
            detail    = entry.get("detail", {}) or {}
            ts        = entry.get("timestamp_utc", "")
            ts_short  = ts[:19].replace("T", " ") if ts else ""

            if action == "PIPELINE_STARTED":
                pass  # captured via ledger start timestamp

            # ── Source node ───────────────────────────────────────────────
            elif action == "SOURCE_REGISTERED":
                nid   = "SOURCE"
                label = detail.get("source_path", "source")
                sha   = (detail.get("sha256", "") or "")[:12]
                sha_disp = sha + "..." if sha else "—"
                rows  = detail.get("row_count", "?")
                current_row_count = rows if isinstance(rows, int) else None
                _add_node(nid, label, "source",
                          {"File": label,
                           "Format": detail.get("file_type", "?"),
                           "Rows":   rows,
                           "Columns": detail.get("col_count", "?"),
                           "SHA-256": sha_disp,
                           "Timestamp": ts_short},
                          icon="\U0001f4c4", rows_out=current_row_count, ts=ts_short)
                source_id = nid
                stage_timestamps["SOURCE"] = ts

            # ── Extract ───────────────────────────────────────────────────
            elif action == "EXTRACT_COMPLETE":
                nid          = "EXTRACT"
                all_columns  = detail.get("columns", [])
                dtypes       = detail.get("dtypes", {})
                rows         = detail.get("rows", current_row_count)
                current_row_count = rows if isinstance(rows, int) else current_row_count
                dur = (
                    round(_parse_ts(ts) - _parse_ts(stage_timestamps.get("SOURCE", ts)), 2)
                    if stage_timestamps.get("SOURCE") else None
                )
                _add_node(nid, "Extract", "transform",
                          {"Stage": "Extract", "Rows": rows,
                           "Columns": len(all_columns),
                           "Timestamp": ts_short},
                          icon=self.STAGE_ICONS["EXTRACT"],
                          rows_out=current_row_count, ts=ts_short, duration_s=dur)
                transform_chain.append(nid)
                stage_timestamps[nid] = ts
                if source_id:
                    _add_edge(source_id, nid, row_count=current_row_count)

            # ── Classification ────────────────────────────────────────────
            elif action == "DATA_CLASSIFIED":
                nid = "CLASSIFY"
                dur = (
                    round(_parse_ts(ts) - _parse_ts(stage_timestamps.get(
                        transform_chain[-1] if transform_chain else "", ts)), 2)
                    if transform_chain else None
                )
                _add_node(nid, "Classify", "transform",
                          {"Stage": "Data Classification",
                           "Level": detail.get("classification_level", "?"),
                           "PII fields": detail.get("pii_fields", 0),
                           "Timestamp": ts_short},
                          icon=self.STAGE_ICONS["CLASSIFY"],
                          rows_out=current_row_count, ts=ts_short, duration_s=dur)
                if transform_chain:
                    _add_edge(transform_chain[-1], nid, row_count=current_row_count)
                transform_chain.append(nid)
                stage_timestamps[nid] = ts

            # ── PII masking ───────────────────────────────────────────────
            elif action == "PII_MASKED":
                pii_fields.add(detail.get("field", ""))

            # ── Validation ────────────────────────────────────────────────
            elif action == "SUITE_RESULT":
                nid    = "VALIDATE"
                passed = detail.get("expectations_passed", 0)
                failed = detail.get("expectations_failed", 0)
                total  = detail.get("expectations_total",  0)
                drops  = 0
                dur = (
                    round(_parse_ts(ts) - _parse_ts(stage_timestamps.get(
                        transform_chain[-1] if transform_chain else "", ts)), 2)
                    if transform_chain else None
                )
                _add_node(nid, "Validate", "transform",
                          {"Stage":   "Great Expectations",
                           "Passed":  f"{passed} / {total}",
                           "Failed":  failed,
                           "Success": str(detail.get("overall_success", "?")),
                           "Timestamp": ts_short},
                          icon=self.STAGE_ICONS["VALIDATE"],
                          rows_out=current_row_count, drops=drops,
                          ts=ts_short, duration_s=dur)
                if transform_chain:
                    _add_edge(transform_chain[-1], nid, row_count=current_row_count)
                transform_chain.append(nid)
                stage_timestamps[nid] = ts

            # ── Null handling ─────────────────────────────────────────────
            elif action == "NULL_HANDLING":
                nid = "NULLS"
                dur = (
                    round(_parse_ts(ts) - _parse_ts(stage_timestamps.get(
                        transform_chain[-1] if transform_chain else "", ts)), 2)
                    if transform_chain else None
                )
                _add_node(nid, "Null Handling", "transform",
                          {"Stage": "Null Handling",
                           "Nulls before": detail.get("null_cells_before", 0),
                           "Nulls after":  detail.get("null_cells_after",  0),
                           "Timestamp": ts_short},
                          icon=self.STAGE_ICONS["NULLS"],
                          rows_out=current_row_count, ts=ts_short, duration_s=dur)
                if transform_chain:
                    _add_edge(transform_chain[-1], nid, row_count=current_row_count)
                transform_chain.append(nid)
                stage_timestamps[nid] = ts

            # ── Deduplication ─────────────────────────────────────────────
            elif action == "DEDUPLICATION":
                nid    = "DEDUP"
                r_bef  = detail.get("rows_before", current_row_count or 0)
                r_aft  = detail.get("rows_after",  current_row_count or 0)
                drops  = detail.get("duplicates_removed", 0)
                total_drops += drops
                current_row_count = r_aft if isinstance(r_aft, int) else current_row_count
                dur = (
                    round(_parse_ts(ts) - _parse_ts(stage_timestamps.get(
                        transform_chain[-1] if transform_chain else "", ts)), 2)
                    if transform_chain else None
                )
                _add_node(nid, "Deduplicate", "transform",
                          {"Stage":   "Deduplication",
                           "Before":  r_bef,
                           "After":   r_aft,
                           "Removed": drops,
                           "Timestamp": ts_short},
                          icon=self.STAGE_ICONS["DEDUP"],
                          rows_out=current_row_count, drops=drops,
                          ts=ts_short, duration_s=dur)
                if transform_chain:
                    _add_edge(transform_chain[-1], nid, row_count=r_bef)
                transform_chain.append(nid)
                stage_timestamps[nid] = ts

            # ── Transform complete ────────────────────────────────────────
            elif action == "TRANSFORM_COMPLETE":
                nid  = "TRANSFORM_DONE"
                rows = detail.get("final_row_count", current_row_count)
                current_row_count = rows if isinstance(rows, int) else current_row_count
                dur = (
                    round(_parse_ts(ts) - _parse_ts(stage_timestamps.get(
                        transform_chain[-1] if transform_chain else "", ts)), 2)
                    if transform_chain else None
                )
                _add_node(nid, "Transform\nComplete", "transform",
                          {"Stage":   "Transform Complete",
                           "Rows":    rows,
                           "Columns": detail.get("final_col_count", len(all_columns)),
                           "Timestamp": ts_short},
                          icon=self.STAGE_ICONS["TRANSFORM_DONE"],
                          rows_out=current_row_count, ts=ts_short, duration_s=dur)
                if transform_chain:
                    _add_edge(transform_chain[-1], nid, row_count=current_row_count)
                transform_chain.append(nid)
                stage_timestamps[nid] = ts
                last_transform_id = nid

            # ── Destination ───────────────────────────────────────────────
            elif action == "DESTINATION_REGISTERED":
                nid   = "DESTINATION"
                db    = detail.get("db_type", "?")
                table = detail.get("table_or_collection", "?")
                dbname = detail.get("db_name", "?")
                _add_node(nid, f"{db} › {table}", "destination",
                          {"Platform": db, "Database": dbname,
                           "Table": table, "Timestamp": ts_short},
                          icon="\U0001f5c4️", rows_out=current_row_count,
                          ts=ts_short)
                destination_id = nid

            # ── Load complete ─────────────────────────────────────────────
            elif action == "LOAD_COMPLETE":
                rows_written = detail.get("rows_written", current_row_count)
                n = next((n for n in nodes if n["id"] == "DESTINATION"), None)
                if n:
                    n["meta"]["Rows written"] = rows_written
                    n["rows_out"] = rows_written

        # ── PII masking consolidated node ─────────────────────────────────
        if pii_fields:
            nid = "MASK_PII"
            pii_ts = next(
                (e.get("timestamp_utc", "")[:19].replace("T", " ")
                 for e in entries if e.get("action") == "PII_MASKED"),
                "",
            )
            classify_idx = next(
                (i for i, n in enumerate(transform_chain) if n == "CLASSIFY"),
                -1,
            )
            insert_after = (
                transform_chain[classify_idx]
                if classify_idx >= 0
                else (transform_chain[-1] if transform_chain else None)
            )
            insert_before = (
                transform_chain[classify_idx + 1]
                if classify_idx >= 0 and classify_idx + 1 < len(transform_chain)
                else None
            )

            _add_node(nid, "Mask PII", "transform",
                      {"Stage":  "PII Masking",
                       "Fields": ", ".join(sorted(pii_fields)),
                       "Count":  len(pii_fields),
                       "Action": "mask / pseudonymise",
                       "Timestamp": pii_ts},
                      icon=self.STAGE_ICONS["MASK_PII"],
                      rows_out=current_row_count, ts=pii_ts)

            if insert_after and insert_before:
                edges[:] = [
                    e for e in edges
                    if not (e["source"] == insert_after and e["target"] == insert_before)
                ]
                _add_edge(insert_after, nid, row_count=current_row_count)
                _add_edge(nid, insert_before, row_count=current_row_count)
                idx = transform_chain.index(insert_before)
                transform_chain.insert(idx, nid)
            elif insert_after:
                _add_edge(insert_after, nid, row_count=current_row_count)
                transform_chain.append(nid)

        # ── Column nodes ──────────────────────────────────────────────────
        if all_columns:
            for col in all_columns:
                is_pii  = col in pii_fields
                nid     = f"COL_{col}"
                raw_dt  = dtypes.get(col, "object")
                dt_lbl  = self.DTYPE_LABELS.get(raw_dt, raw_dt[:6])
                _add_node(nid, col, "pii_column" if is_pii else "column",
                          {"Column": col,
                           "Type":   raw_dt,
                           "PII":    "Yes — masked" if is_pii else "No"},
                          icon="\U0001f512" if is_pii else "\U0001f4ca",
                          rows_out=current_row_count)
                # Attach dtype label directly on the node dict for JS
                nodes[-1]["dtype"] = dt_lbl

            anchor = last_transform_id or (transform_chain[-1] if transform_chain else None)
            if anchor:
                for col in all_columns:
                    _add_edge(anchor, f"COL_{col}", "dashed", current_row_count)
            if destination_id:
                for col in all_columns:
                    _add_edge(f"COL_{col}", destination_id, "dashed", current_row_count)

        elif destination_id and last_transform_id:
            _add_edge(last_transform_id, destination_id, row_count=current_row_count)

        return nodes, edges

    # ── HTML renderer ─────────────────────────────────────────────────────

    def generate(self, output_path: str | None = None) -> str:
        """
        Build the improved lineage graph and write a self-contained HTML file.

        Parameters
        ----------
        output_path : str | None
            Defaults to ``<gov_log_dir>/lineage_<ts>.html``.

        Returns
        -------
        str  Path to the saved HTML file.
        """
        nodes, edges = self._build_graph()
        ts    = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        path  = output_path or str(self.gov.log_dir / f"lineage_{ts}.html")
        run_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        nodes_json = json.dumps(nodes, default=str)
        edges_json = json.dumps(edges, default=str)

        html = self._render_html(ts, run_ts, nodes_json, edges_json)

        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(html, encoding="utf-8")
        self.gov.transformation_applied("LINEAGE_GRAPH_SAVED", {
            "path":  path,
            "nodes": len(nodes),
            "edges": len(edges),
            "version": "v2",
        })
        logger.info("Lineage graph saved to %s (%d nodes, %d edges)",
                     path, len(nodes), len(edges))
        return path

    # ── HTML template ─────────────────────────────────────────────────────

    @staticmethod
    def _render_html(
        ts: str,
        run_ts: str,
        nodes_json: str,
        edges_json: str,
    ) -> str:
        """Build the full self-contained HTML string for the lineage graph."""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Data Lineage — {ts}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.9.0/d3.min.js"></script>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:system-ui,sans-serif;background:#0d1117;color:#e6edf3;overflow:hidden;user-select:none}}

/* ── Toolbar ── */
#toolbar{{position:fixed;top:0;left:0;right:0;height:50px;background:#161b22;
          border-bottom:1px solid #30363d;display:flex;align-items:center;
          padding:0 16px;gap:12px;z-index:200}}
#toolbar h1{{font-size:.95em;font-weight:600;color:#58a6ff;white-space:nowrap}}
#toolbar .sep{{width:1px;height:24px;background:#30363d}}
.filter-btn{{display:flex;align-items:center;gap:5px;padding:4px 10px;border-radius:20px;
             border:1px solid #30363d;background:transparent;color:#8b949e;
             font-size:.78em;cursor:pointer;transition:all .15s}}
.filter-btn.active{{background:#1f6feb22;border-color:#1f6feb;color:#58a6ff}}
.filter-btn:hover{{border-color:#8b949e;color:#e6edf3}}
.dot{{width:8px;height:8px;border-radius:50%;display:inline-block}}
#search{{margin-left:auto;background:#0d1117;border:1px solid #30363d;color:#e6edf3;
         padding:5px 12px;border-radius:20px;font-size:.8em;outline:none;width:180px}}
#search:focus{{border-color:#58a6ff}}
#search::placeholder{{color:#484f58}}
#export-btn{{padding:5px 12px;background:#238636;border:none;color:#fff;border-radius:6px;
             font-size:.8em;cursor:pointer;display:flex;align-items:center;gap:5px}}
#export-btn:hover{{background:#2ea043}}
#run-ts{{font-size:.72em;color:#484f58;white-space:nowrap}}

/* ── Canvas ── */
#canvas{{position:fixed;top:50px;left:0;right:0;bottom:0}}
svg#main{{width:100%;height:100%}}

/* ── Edges ── */
.link{{stroke:#30363d;stroke-opacity:.8;fill:none;stroke-width:1.5}}
.link-dashed{{stroke:#1f6feb;stroke-opacity:.4;stroke-dasharray:5 4;fill:none;stroke-width:1}}
.link.dimmed,.link-dashed.dimmed{{opacity:.04}}
.edge-label{{font-size:9px;fill:#6e7681;text-anchor:middle;pointer-events:none}}

/* ── Nodes ── */
.node{{cursor:pointer;transition:opacity .2s}}
.node.dimmed{{opacity:.07}}
.node.focused rect,.node.focused circle,.node.focused .col-pill{{filter:brightness(1.35);stroke-width:2.5px!important}}

/* Source pill */
.node-source .n-pill{{fill:#0c2d6b;stroke:#58a6ff;stroke-width:1.5;rx:22}}
.node-source text{{fill:#cae8ff;font-size:11px;font-weight:600}}

/* Destination pill */
.node-destination .n-pill{{fill:#0a2d0a;stroke:#3fb950;stroke-width:1.5;rx:22}}
.node-destination text{{fill:#7ee787;font-size:11px;font-weight:600}}

/* Transform box */
.node-transform .n-box{{fill:#161b22;stroke:#30363d;stroke-width:1.2;rx:10}}
.node-transform text{{fill:#c9d1d9;font-size:11px}}
.node-transform .n-icon{{font-size:14px}}
.n-dur{{font-size:8px;fill:#6e7681}}

/* Column pill */
.col-pill{{rx:10;stroke-width:1.2}}
.node-column .col-pill{{fill:#0d1117;stroke:#1f6feb}}
.node-pii_column .col-pill{{fill:#1f0a0a;stroke:#f85149}}
.node-column text,.node-pii_column text{{font-size:10px}}
.dtype-badge{{font-size:8px;fill:#484f58}}

/* Drop badge */
.drop-badge rect{{fill:#6e292c;rx:4}}
.drop-badge text{{font-size:8px;fill:#f85149;font-weight:600}}

/* ── Tooltip ── */
#tip{{position:fixed;background:#1c2128;border:1px solid #30363d;border-radius:8px;
      padding:10px 14px;font-size:.78em;pointer-events:none;display:none;
      max-width:260px;box-shadow:0 8px 24px rgba(0,0,0,.6);z-index:300}}
#tip h4{{color:#58a6ff;margin-bottom:7px;font-size:.85em}}
#tip table{{border-collapse:collapse;width:100%}}
#tip td{{padding:2px 4px;vertical-align:top}}
#tip td:first-child{{color:#8b949e;white-space:nowrap;padding-right:10px}}
#tip td:last-child{{color:#e6edf3;word-break:break-all}}

/* ── Minimap ── */
#minimap-wrap{{position:fixed;bottom:16px;right:16px;border:1px solid #30363d;
               background:#0d1117;border-radius:8px;overflow:hidden;z-index:150}}
#minimap{{width:160px;height:110px;display:block}}
#mm-viewport{{fill:#58a6ff22;stroke:#58a6ff;stroke-width:.5}}

/* ── Stats bar ── */
#stats{{position:fixed;bottom:16px;left:16px;background:#161b22;border:1px solid #30363d;
        border-radius:20px;padding:5px 14px;font-size:.73em;color:#8b949e;z-index:150}}
</style>
</head>
<body>

<div id="toolbar">
  <h1>\U0001f517 Data Lineage</h1>
  <span class="sep"></span>
  <button class="filter-btn active" id="f-transforms" onclick="toggleFilter('transforms')">
    <span class="dot" style="background:#8b949e"></span>Transforms
  </button>
  <button class="filter-btn active" id="f-columns" onclick="toggleFilter('columns')">
    <span class="dot" style="background:#1f6feb"></span>Columns
  </button>
  <button class="filter-btn active" id="f-pii" onclick="toggleFilter('pii')">
    <span class="dot" style="background:#f85149"></span>PII
  </button>
  <span class="sep"></span>
  <span id="run-ts">{run_ts}</span>
  <input id="search" placeholder="\U0001f50d  Search nodes..." type="text">
  <button id="export-btn" onclick="exportPNG()">⬇ PNG</button>
</div>

<div id="canvas"><svg id="main"></svg></div>
<div id="tip"><h4 id="tip-title"></h4><table id="tip-body"></table></div>
<div id="minimap-wrap"><svg id="minimap"><rect id="mm-viewport"/></svg></div>
<div id="stats"></div>

<script>
const NODES = {nodes_json};
const EDGES = {edges_json};

// ── State ────────────────────────────────────────────────────────────────
const filters = {{transforms:true, columns:true, pii:true}};
let focusedId  = null;

// ── SVG / zoom setup ────────────────────────────────────────────────────
const svg    = d3.select("#main");
const W = () => +svg.node().clientWidth;
const H = () => +svg.node().clientHeight;

const defs = svg.append("defs");
// Arrowheads
[["arr-grey","#30363d",14],["arr-blue","#1f6feb",12]].forEach(([id,col,ref]) => {{
  defs.append("marker").attr("id",id)
    .attr("viewBox","0 -4 8 8").attr("refX",ref).attr("refY",0)
    .attr("markerWidth",5).attr("markerHeight",5).attr("orient","auto")
    .append("path").attr("d","M0,-4L8,0L0,4").attr("fill",col).attr("opacity",.7);
}});

const gZoom = svg.append("g").attr("class","zoom-root");
const zoom  = d3.zoom().scaleExtent([.05,4]).on("zoom", e => {{
  gZoom.attr("transform", e.transform);
  updateMinimap(e.transform);
}});
svg.call(zoom).on("dblclick.zoom", null);

// ── Build node lookup ────────────────────────────────────────────────────
const nodeById = Object.fromEntries(NODES.map(n=>[n.id,n]));

// ── Force simulation ─────────────────────────────────────────────────────
const bandX = {{source:.08, transform:.38, column:.68, pii_column:.68, destination:.95}};

const sim = d3.forceSimulation(NODES)
  .force("link",   d3.forceLink(EDGES).id(d=>d.id)
                     .distance(d => d.style==="dashed" ? 80 : 120).strength(.5))
  .force("charge", d3.forceManyBody()
                     .strength(d => (d.type==="column"||d.type==="pii_column") ? -60 : -350))
  .force("x",      d3.forceX(d=>(bandX[d.type]||.4)*W()).strength(.55))
  .force("y",      d3.forceY(H()/2).strength(.08))
  .force("collide",d3.forceCollide(d=>(d.type==="column"||d.type==="pii_column")?30:58));

// ── Draw curved edges ────────────────────────────────────────────────────
const linkG = gZoom.append("g").attr("class","links");
const link  = linkG.selectAll("g").data(EDGES).join("g");

const linkPath = link.append("path")
  .attr("class", d => d.style==="dashed"?"link-dashed":"link")
  .attr("marker-end", d => d.style==="dashed"?"url(#arr-blue)":"url(#arr-grey)");

const linkLabel = link.append("text").attr("class","edge-label")
  .text(d => d.row_count != null ? d.row_count.toLocaleString()+"r" : "")
  .style("display", d => (d.style==="dashed"||!d.row_count) ? "none":"block");

// ── Draw nodes ───────────────────────────────────────────────────────────
const nodeG = gZoom.append("g").attr("class","nodes");
const node  = nodeG.selectAll("g.node").data(NODES).join("g")
  .attr("class", d=>`node node-${{d.type}}`)
  .call(d3.drag()
    .on("start",(e,d)=>{{if(!e.active)sim.alphaTarget(.3).restart();d.fx=d.x;d.fy=d.y}})
    .on("drag", (e,d)=>{{d.fx=e.x;d.fy=e.y}})
    .on("end",  (e,d)=>{{if(!e.active)sim.alphaTarget(0);d.fx=null;d.fy=null}}))
  .on("mousemove",(e,d)=>showTip(e,d))
  .on("mouseleave",()=>hideTip())
  .on("click",(e,d)=>{{e.stopPropagation();toggleFocus(d)}});

svg.on("click", ()=>clearFocus());

// Build each node shape
node.each(function(d){{
  const el = d3.select(this);
  const isCol = d.type==="column"||d.type==="pii_column";

  if(d.type==="source"||d.type==="destination"){{
    const w = Math.max(140, d.label.length*8+48);
    el.append("rect").attr("class","n-pill").attr("width",w).attr("height",34)
      .attr("x",-w/2).attr("y",-17).attr("rx",17);
    el.append("text").attr("class","n-icon").attr("x",-w/2+14).attr("y",1)
      .attr("dominant-baseline","central").text(d.icon||"");
    el.append("text").attr("x",8).attr("y",0).attr("dominant-baseline","central")
      .text(d.label.length>22?d.label.slice(0,21)+"...":d.label);
    if(d.rows_out!=null){{
      el.append("text").attr("class","n-dur").attr("x",0).attr("y",22).attr("text-anchor","middle")
        .text(d.rows_out.toLocaleString()+" rows");
    }}
  }} else if(isCol){{
    const lbl   = d.label.length>14?d.label.slice(0,13)+"...":d.label;
    const dtype = d.dtype||"";
    const w = Math.max(70, lbl.length*7.5+24+(dtype?dtype.length*5.5+8:0));
    el.append("rect").attr("class","col-pill").attr("width",w).attr("height",22)
      .attr("x",-w/2).attr("y",-11).attr("rx",11);
    el.append("text").attr("x", dtype ? -w/2+8 : 0).attr("y",0)
      .attr("dominant-baseline","central")
      .attr("text-anchor", dtype?"start":"middle").text(lbl)
      .style("fill", d.type==="pii_column"?"#ffa198":"#79c0ff");
    if(dtype){{
      const bx = w/2-dtype.length*5.5-8;
      el.append("rect").attr("x",bx-4).attr("y",-7).attr("width",dtype.length*5.5+8)
        .attr("height",14).attr("rx",3).style("fill","#161b22").style("stroke","#30363d").style("stroke-width","0.8");
      el.append("text").attr("class","dtype-badge").attr("x",bx+dtype.length*2.75)
        .attr("y",0).attr("dominant-baseline","central").attr("text-anchor","middle").text(dtype);
    }}
  }} else {{
    // Transform box
    const lines  = d.label.split("\\n");
    const w      = Math.max(110, d.label.replace("\\n"," ").length*8+40);
    const h      = lines.length>1?52:42;
    el.append("rect").attr("class","n-box").attr("width",w).attr("height",h)
      .attr("x",-w/2).attr("y",-h/2).attr("rx",10);
    // Icon
    if(d.icon){{
      el.append("text").attr("class","n-icon").attr("x",-w/2+12).attr("y",0)
        .attr("dominant-baseline","central").text(d.icon);
    }}
    // Label lines
    const xOff = d.icon?4:0;
    lines.forEach((ln,i)=>{{
      el.append("text").attr("x",xOff).attr("y",(i-(lines.length-1)/2)*14)
        .attr("dominant-baseline","central").attr("text-anchor","middle").text(ln);
    }});
    // Duration badge
    if(d.duration_s!=null){{
      el.append("text").attr("class","n-dur").attr("x",0).attr("y",h/2-6)
        .attr("text-anchor","middle").text(d.duration_s+"s");
    }}
    // Drop badge (if any rows dropped)
    if(d.drops&&d.drops>0){{
      const g2 = el.append("g").attr("class","drop-badge").attr("transform",`translate(${{w/2-4}},${{-h/2-2}})`);
      const lbl = `-${{d.drops}}`;
      g2.append("rect").attr("x",-lbl.length*4.5-4).attr("y",-8).attr("width",lbl.length*4.5+8).attr("height",14).attr("rx",4);
      g2.append("text").attr("x",-lbl.length*2.25+0.5).attr("y",0).attr("dominant-baseline","central").text(lbl);
    }}
  }}
}});

// ── Tick: bezier paths ───────────────────────────────────────────────────
sim.on("tick", () => {{
  linkPath.attr("d", d => {{
    const sx=d.source.x, sy=d.source.y, tx=d.target.x, ty=d.target.y;
    const cx = (sx+tx)/2;
    return `M${{sx}},${{sy}} C${{cx}},${{sy}} ${{cx}},${{ty}} ${{tx}},${{ty}}`;
  }});
  linkLabel.attr("x",d=>(d.source.x+d.target.x)/2).attr("y",d=>(d.source.y+d.target.y)/2-5);
  node.attr("transform",d=>`translate(${{d.x}},${{d.y}})`);
  updateMinimapNodes();
}});

// ── Entrance animation ────────────────────────────────────────────────────
// Start all nodes off-screen-left, fade in by band
const bandOrder = ["source","transform","column","pii_column","destination"];
NODES.forEach(n => {{ n.x = -300; n.y = H()/2; }});
sim.alpha(1).restart();

setTimeout(() => {{
  bandOrder.forEach((band, bi) => {{
    setTimeout(() => {{
      node.filter(d=>d.type===band)
        .transition().duration(600).ease(d3.easeCubicOut)
        .style("opacity",1);
    }}, bi*150);
  }});
}}, 200);

// Start nodes invisible and reveal
node.style("opacity",0);

// ── Tooltip ──────────────────────────────────────────────────────────────
const tip = document.getElementById("tip");
function showTip(e,d){{
  document.getElementById("tip-title").textContent = (d.icon?d.icon+" ":"")+d.label.replace("\\n"," ");
  const rows = Object.entries(d.meta||{{}}).map(([k,v])=>
    `<tr><td>${{k}}</td><td>${{String(v).slice(0,80)}}</td></tr>`).join("");
  document.getElementById("tip-body").innerHTML = rows||"<tr><td>No metadata</td></tr>";
  tip.style.display = "block";
  moveTip(e);
}}
function moveTip(e){{
  const t=tip, x=e.clientX+14, y=e.clientY-10;
  t.style.left = (x+t.offsetWidth>window.innerWidth ? x-t.offsetWidth-28 : x)+"px";
  t.style.top  = (y+t.offsetHeight>window.innerHeight ? y-t.offsetHeight : y)+"px";
}}
function hideTip(){{ tip.style.display="none"; }}
svg.node().addEventListener("mousemove", e=>{{ if(tip.style.display!=="none") moveTip(e); }});

// ── Focus mode ────────────────────────────────────────────────────────────
function getLineage(d){{
  const ids = new Set([d.id]);
  // Traverse upstream and downstream
  let frontier = [d.id];
  for(let pass=0;pass<30&&frontier.length;pass++){{
    const next=[];
    EDGES.forEach(e=>{{
      const s=typeof e.source==="object"?e.source.id:e.source;
      const t=typeof e.target==="object"?e.target.id:e.target;
      if(frontier.includes(s)&&!ids.has(t)){{ids.add(t);next.push(t);}}
      if(frontier.includes(t)&&!ids.has(s)){{ids.add(s);next.push(s);}}
    }});
    frontier=next;
  }}
  return ids;
}}
function toggleFocus(d){{
  if(focusedId===d.id){{ clearFocus(); return; }}
  focusedId = d.id;
  const ids = getLineage(d);
  node.classed("dimmed",n=>!ids.has(n.id)).classed("focused",n=>n.id===d.id);
  link.classed("dimmed",e=>{{
    const s=typeof e.source==="object"?e.source.id:e.source;
    const t=typeof e.target==="object"?e.target.id:e.target;
    return !ids.has(s)||!ids.has(t);
  }});
}}
function clearFocus(){{
  focusedId=null;
  node.classed("dimmed",false).classed("focused",false);
  link.classed("dimmed",false);
}}

// ── Filter toggles ────────────────────────────────────────────────────────
function toggleFilter(key){{
  filters[key] = !filters[key];
  document.getElementById("f-"+key).classList.toggle("active", filters[key]);
  applyFilters();
}}
function applyFilters(){{
  node.style("display", d=>{{
    if(d.type==="transform"&&!filters.transforms) return "none";
    if(d.type==="column"&&!filters.columns) return "none";
    if(d.type==="pii_column"&&(!filters.pii||!filters.columns)) return "none";
    return null;
  }});
  link.style("display", e=>{{
    const s=typeof e.source==="object"?nodeById[e.source.id]:nodeById[e.source];
    const t=typeof e.target==="object"?nodeById[e.target.id]:nodeById[e.target];
    if(!s||!t) return null;
    const sHid = (s.type==="transform"&&!filters.transforms)||(s.type==="column"&&!filters.columns)||(s.type==="pii_column"&&(!filters.pii||!filters.columns));
    const tHid = (t.type==="transform"&&!filters.transforms)||(t.type==="column"&&!filters.columns)||(t.type==="pii_column"&&(!filters.pii||!filters.columns));
    return sHid||tHid ? "none" : null;
  }});
}}

// ── Search ────────────────────────────────────────────────────────────────
document.getElementById("search").addEventListener("input", function(){{
  const q=this.value.toLowerCase().trim();
  if(!q){{clearFocus();return;}}
  const matched=new Set(NODES.filter(n=>n.label.toLowerCase().includes(q)||
    Object.values(n.meta||{{}}).join(" ").toLowerCase().includes(q)).map(n=>n.id));
  node.classed("dimmed",n=>!matched.has(n.id));
  link.classed("dimmed",e=>{{
    const s=typeof e.source==="object"?e.source.id:e.source;
    const t=typeof e.target==="object"?e.target.id:e.target;
    return !matched.has(s)||!matched.has(t);
  }});
}});

// ── Export to PNG ─────────────────────────────────────────────────────────
function exportPNG(){{
  const svgEl  = document.getElementById("main");
  const clone  = svgEl.cloneNode(true);
  clone.setAttribute("xmlns","http://www.w3.org/2000/svg");
  clone.setAttribute("width",W());clone.setAttribute("height",H());
  // Embed dark background
  const bg=document.createElementNS("http://www.w3.org/2000/svg","rect");
  bg.setAttribute("width","100%");bg.setAttribute("height","100%");bg.setAttribute("fill","#0d1117");
  clone.insertBefore(bg,clone.firstChild);
  const xml = new XMLSerializer().serializeToString(clone);
  const img = new Image();
  img.onload=()=>{{
    const c=document.createElement("canvas");c.width=W();c.height=H();
    const ctx=c.getContext("2d");ctx.drawImage(img,0,0);
    const a=document.createElement("a");a.download="lineage_{ts}.png";
    a.href=c.toDataURL("image/png");a.click();
  }};
  img.src="data:image/svg+xml;charset=utf-8,"+encodeURIComponent(xml);
}}

// ── Minimap ───────────────────────────────────────────────────────────────
const mm      = d3.select("#minimap");
const mmW     = 160, mmH = 110;
const mmNodes = mm.append("g");
const mmVP    = document.getElementById("mm-viewport");
let mmScale   = 1, mmTx = 0, mmTy = 0;

function updateMinimap(t){{
  mmScale=t.k; mmTx=t.x; mmTy=t.y;
  const vpW=W()/t.k, vpH=H()/t.k;
  const sx=-t.x/t.k, sy=-t.y/t.k;
  const bb=getGraphBB();
  if(!bb||bb.w===0) return;
  const scl=Math.min(mmW/bb.w, mmH/bb.h)*.85;
  const ox=(mmW-bb.w*scl)/2-bb.minX*scl, oy=(mmH-bb.h*scl)/2-bb.minY*scl;
  mmNodes.attr("transform",`translate(${{ox}},${{oy}}) scale(${{scl}})`);
  d3.select(mmVP)
    .attr("x",sx*scl+ox-4).attr("y",sy*scl+oy-4)
    .attr("width",(vpW*scl)+8).attr("height",(vpH*scl)+8);
}}
function getGraphBB(){{
  if(!NODES.length||!NODES[0].x) return null;
  const xs=NODES.map(n=>n.x||0), ys=NODES.map(n=>n.y||0);
  return {{minX:Math.min(...xs),minY:Math.min(...ys),w:Math.max(...xs)-Math.min(...xs)||1,h:Math.max(...ys)-Math.min(...ys)||1}};
}}
function updateMinimapNodes(){{
  const dots=mmNodes.selectAll("circle").data(NODES);
  dots.join("circle").attr("cx",d=>d.x||0).attr("cy",d=>d.y||0).attr("r",4)
    .attr("fill",d=>{{
      if(d.type==="source")      return "#58a6ff";
      if(d.type==="destination") return "#3fb950";
      if(d.type==="pii_column") return "#f85149";
      if(d.type==="column")      return "#1f6feb";
      return "#8b949e";
    }}).attr("opacity",.8);
}}

// ── Stats ─────────────────────────────────────────────────────────────────
const piiCnt = NODES.filter(n=>n.type==="pii_column").length;
const colCnt  = NODES.filter(n=>n.type==="column"||n.type==="pii_column").length;
const trnCnt  = NODES.filter(n=>n.type==="transform").length;
document.getElementById("stats").textContent =
  `${{NODES.length}} nodes · ${{EDGES.length}} edges · ${{trnCnt}} stages · ${{colCnt}} columns (${{piiCnt}} PII)`;

// ── Auto-fit after simulation settles ────────────────────────────────────
let fitted=false;
sim.on("end",()=>{{
  if(fitted) return; fitted=true;
  const bb=getGraphBB();
  if(!bb||bb.w===0) return;
  const pad=80;
  const scl=Math.min(.92,Math.min(W()/(bb.w+pad),(H())/(bb.h+pad)));
  const tx=W()/2-scl*(bb.minX+bb.w/2), ty=H()/2-scl*(bb.minY+bb.h/2);
  svg.transition().duration(800).call(zoom.transform,d3.zoomIdentity.translate(tx,ty).scale(scl));
}});
window.addEventListener("resize",()=>sim.alpha(.15).restart());
</script>
</body>
</html>"""
