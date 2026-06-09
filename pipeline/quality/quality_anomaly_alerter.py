"""
Quality anomaly alerter — monitors quality score trends and fires alerts.

Layer 3 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-07   Initial extraction from pipeline_v3.py.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


class QualityAnomalyAlerter:
    """
    Monitors data quality score trends across runs and fires alerts when
    anomalies are detected — before bad data reaches production.

    Detection methods
    -----------------
    THRESHOLD DROP     Score falls more than ``drop_threshold`` points from
                       the previous run in a single step.

    ROLLING DECLINE    Score has declined consistently over the past
                       ``rolling_window`` runs (every run lower than the one
                       before). Catches slow, gradual degradation.

    DIMENSION SPIKE    Any single dimension (completeness, uniqueness, etc.)
                       drops more than ``dimension_threshold`` points in one
                       run.  Catches targeted problems invisible in the
                       composite score.

    FLOOR BREACH       Composite score drops below the configured
                       ``absolute_floor``.  Hard minimum — always fires
                       regardless of trend.

    Alert channels
    --------------
    Each channel is optional and independently configurable:

    console    Always enabled. Logs a formatted alert block.
    log_file   Appends JSON alert records to ``alert_log_file``.
    slack      HTTP POST to a Slack incoming webhook URL.
    email      SMTP email via smtplib (TLS).  Requires smtp_cfg dict.
    webhook    HTTP POST to any arbitrary URL with a JSON payload.
    governance Writes a QUALITY_ANOMALY_ALERT event to the GovernanceLogger
               ledger.  Always enabled if a gov instance is provided.

    Quick-start
    -----------
        from pipeline.quality import QualityAnomalyAlerter
        alerter = QualityAnomalyAlerter(gov)
        alerter.check(current_score_report)

    Parameters
    ----------
    gov                 : GovernanceLogger | None
    drop_threshold      : float   Composite drop that triggers an alert (default 10).
    dimension_threshold : float   Per-dimension drop threshold (default 15).
    absolute_floor      : float   Hard minimum composite score (default 60).
    rolling_window      : int     Consecutive declining runs to trigger alert (default 3).
    history_file        : str | Path   Quality score history (read-only).
    alert_log_file      : str | Path   Where alert records are appended.
    slack_webhook       : str | None   Slack incoming webhook URL.
    email_cfg           : dict | None  SMTP config dict.
    webhook_url         : str | None   Generic HTTP webhook URL.
    """

    def __init__(
        self,
        gov=None,
        drop_threshold:      float          = 10.0,
        dimension_threshold: float          = 15.0,
        absolute_floor:      float          = 60.0,
        rolling_window:      int            = 3,
        history_file:        str | Path | None = None,
        alert_log_file:      str | Path     = "quality_alerts.jsonl",
        slack_webhook:       str | None     = None,
        email_cfg:           dict | None    = None,
        webhook_url:         str | None     = None,
    ) -> None:
        self.gov                 = gov
        self.drop_threshold      = drop_threshold
        self.dimension_threshold = dimension_threshold
        self.absolute_floor      = absolute_floor
        self.rolling_window      = rolling_window
        # history_file defaults to gov.quality_log_file when gov is provided
        if history_file is not None:
            self.history_file = Path(history_file)
        elif gov is not None and hasattr(gov, "quality_log_file"):
            self.history_file = Path(gov.quality_log_file)
        else:
            self.history_file = Path("quality_history.jsonl")
        self.alert_log_file      = Path(alert_log_file)
        self.slack_webhook       = slack_webhook
        self.email_cfg           = email_cfg
        self.webhook_url         = webhook_url

    # ── History helpers ───────────────────────────────────────────────────

    def _load_history(self, n: int = 50) -> list[dict]:
        """Return the last n records from the quality score history file."""
        if not self.history_file.exists():
            return []
        records = []
        for line in self.history_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return records[-n:]

    def _prev_record(self) -> dict | None:
        """Return the second-to-last record (the run before the current one)."""
        hist = self._load_history(n=10)
        return hist[-2] if len(hist) >= 2 else None

    # ── Anomaly detectors ─────────────────────────────────────────────────

    def _check_threshold_drop(
        self, current: dict, previous: dict
    ) -> dict | None:
        curr_score = float(current.get("score", 100.0))
        prev_score = float(previous.get("score", 100.0))
        drop       = prev_score - curr_score
        if drop > self.drop_threshold:
            return {
                "type":        "THRESHOLD_DROP",
                "severity":    "HIGH" if drop > self.drop_threshold * 2 else "MEDIUM",
                "message":     f"Quality score dropped {drop:.1f} points "
                               f"({prev_score:.1f} -> {curr_score:.1f})",
                "drop":        round(float(drop), 2),
                "threshold":   self.drop_threshold,
                "prev_score":  prev_score,
                "curr_score":  curr_score,
            }
        return None

    def _check_floor_breach(self, current: dict) -> dict | None:
        score = current.get("score", 100.0)
        if score < self.absolute_floor:
            return {
                "type":     "FLOOR_BREACH",
                "severity": "CRITICAL",
                "message":  f"Quality score {score:.1f} is below the minimum "
                            f"floor of {self.absolute_floor}",
                "score":    score,
                "floor":    self.absolute_floor,
                "gap":      round(self.absolute_floor - score, 2),
            }
        return None

    def _check_rolling_decline(self) -> dict | None:
        hist = self._load_history(n=self.rolling_window + 1)
        if len(hist) < self.rolling_window:
            return None
        # Check last rolling_window records are strictly declining
        recent = [r.get("score", 100.0) for r in hist[-(self.rolling_window):]]
        if all(recent[i] > recent[i + 1] for i in range(len(recent) - 1)):
            total_drop = recent[0] - recent[-1]
            return {
                "type":       "ROLLING_DECLINE",
                "severity":   "HIGH",
                "message":    f"Quality score has declined for {self.rolling_window} "
                              f"consecutive runs (total drop: {total_drop:.1f} pts)",
                "window":     self.rolling_window,
                "scores":     [round(s, 1) for s in recent],
                "total_drop": round(total_drop, 2),
            }
        return None

    def _check_dimension_spikes(
        self, current: dict, previous: dict
    ) -> list[dict]:
        alerts = []
        curr_dims = current.get("dimensions",  {})
        prev_dims = previous.get("dimensions", {})
        for dim, curr_val in curr_dims.items():
            prev_val = prev_dims.get(dim)
            if prev_val is None:
                continue
            try:
                curr_val = float(curr_val)
                prev_val = float(prev_val)
            except (ValueError, TypeError):
                logger.debug("Non-numeric dimension %r values: curr=%r prev=%r — skipped", dim, curr_val, prev_val)
                continue
            drop = prev_val - curr_val
            if drop > self.dimension_threshold:
                severity = "HIGH" if drop > self.dimension_threshold * 1.5 else "MEDIUM"
                alerts.append({
                    "type":      "DIMENSION_SPIKE",
                    "severity":  severity,
                    "message":   f"Dimension '{dim}' dropped {drop:.1f} points "
                                 f"({prev_val:.1f} -> {curr_val:.1f})",
                    "dimension": dim,
                    "drop":      round(float(drop), 2),
                    "threshold": self.dimension_threshold,
                    "prev_val":  prev_val,
                    "curr_val":  curr_val,
                })
        return alerts

    # ── Main entry point ──────────────────────────────────────────────────

    def check(self, current_report, label: str = "") -> list[dict]:
        """
        Run all anomaly checks against the current quality score report
        and fire alerts for any anomalies found.

        Call this immediately after DataQualityScorer.score() to get
        preventive alerting on every run.

        Parameters
        ----------
        current_report : dict | pd.DataFrame
            Either the dict returned by DataQualityScorer.score(), or a
            raw DataFrame (score will be computed automatically using a
            default DataQualityScorer).
        label          : str   Optional label stored in the alert records.

        Returns
        -------
        list[dict]  All alerts fired during this check (empty = no anomalies).
        """
        # Accept raw DataFrame as a convenience — auto-score it
        import pandas as _pd  # pylint: disable=import-outside-toplevel
        if isinstance(current_report, _pd.DataFrame):
            from pipeline.quality.data_quality_scorer import DataQualityScorer
            _qs = DataQualityScorer(gov=self.gov)
            current_report = _qs.score(current_report)

        previous = self._prev_record()
        alerts   = []

        # Run all detectors
        floor_alert = self._check_floor_breach(current_report)
        if floor_alert:
            alerts.append(floor_alert)

        if previous:
            drop_alert = self._check_threshold_drop(current_report, previous)
            if drop_alert:
                alerts.append(drop_alert)

            dim_alerts = self._check_dimension_spikes(current_report, previous)
            alerts.extend(dim_alerts)

        rolling_alert = self._check_rolling_decline()
        if rolling_alert:
            alerts.append(rolling_alert)

        # Fire each alert through all configured channels
        for alert in alerts:
            self._dispatch(alert, current_report)

        if not alerts:
            # Log a clean bill of health to governance
            if self.gov:
                self.gov.transformation_applied("QUALITY_CHECK_PASSED", {
                    "score":    current_report.get("score"),
                    "grade":    current_report.get("grade"),
                    "note":     "No anomalies detected",
                })

        return alerts

    # ── Alert dispatcher ──────────────────────────────────────────────────

    def _dispatch(self, alert: dict, report: dict) -> None:
        """Route a single alert to every configured channel."""
        ts      = datetime.now(timezone.utc).isoformat()
        payload = {
            "timestamp":   ts,
            "alert":       alert,
            "score":       report.get("score"),
            "grade":       report.get("grade"),
            "dimensions":  report.get("dimensions", {}),
            "run_label":   report.get("run_label"),
        }

        # 1. Console (via logger)
        self._alert_console(alert, report)

        # 2. Governance ledger
        if self.gov:
            self.gov.transformation_applied("QUALITY_ANOMALY_ALERT", {
                "type":     alert["type"],
                "severity": alert["severity"],
                "message":  alert["message"],
                "score":    report.get("score"),
            })

        # 3. Append to alert log file
        try:
            with open(self.alert_log_file, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(payload, default=str) + "\n")
        except OSError as exc:
            logger.warning("Could not write alert log: %s", exc)

        # 4. Slack webhook
        if self.slack_webhook:
            self._alert_slack(alert, report)

        # 5. Email
        if self.email_cfg:
            self._alert_email(alert, report)

        # 6. Generic webhook
        if self.webhook_url:
            self._alert_webhook(payload)

    def _alert_console(self, alert: dict, report: dict) -> None:
        """Log a formatted alert block."""
        sev    = alert.get("severity", "MEDIUM")
        border = "=" * 62
        logger.warning(
            "\n  %s\n  QUALITY ANOMALY ALERT  [%s]\n  %s\n"
            "  Type    : %s\n  Message : %s\n  Score   : %s (grade %s)\n  %s",
            border, sev, border,
            alert["type"], alert["message"],
            report.get("score", "?"), report.get("grade", "?"),
            border,
        )

    def _alert_slack(self, alert: dict, report: dict) -> None:
        """POST a Slack Block Kit message to the incoming webhook."""
        text = (
            f"*Data Quality Alert [{alert.get('severity')}]*\n"
            f"*{alert['type']}* — {alert['message']}\n"
            f"Current score: `{report.get('score', '?')}` (grade `{report.get('grade', '?')}`)"
        )
        payload = {"text": text, "username": "Pipeline Quality Bot",
                   "icon_emoji": ":bar_chart:"}
        try:
            import urllib.request as _req  # pylint: disable=import-outside-toplevel
            data = json.dumps(payload).encode("utf-8")
            req  = _req.Request(self.slack_webhook, data=data,  # type: ignore[arg-type]
                                headers={"Content-Type": "application/json"})
            with _req.urlopen(req, timeout=5):
                pass
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning("Slack send failed: %s", exc)

    def _alert_email(self, alert: dict, report: dict) -> None:
        """Send an SMTP email alert."""
        cfg = self.email_cfg or {}
        try:
            import smtplib  # pylint: disable=import-outside-toplevel
            from email.mime.text import MIMEText  # pylint: disable=import-outside-toplevel
            subject = (
                f"{cfg.get('subject_prefix','[Alert]')} Quality {alert['type']} "
                f"— score {report.get('score','?')}"
            )
            dims_txt = "\n".join(
                f"  {k}: {v:.1f}" for k, v in report.get("dimensions", {}).items()
            )
            body = (
                "Data Quality Anomaly Detected\n"
                f"{'='*40}\n"
                f"Type     : {alert['type']}\n"
                f"Severity : {alert.get('severity')}\n"
                f"Message  : {alert['message']}\n\n"
                f"Current Score : {report.get('score','?')} (grade {report.get('grade','?')})\n\n"
                f"Dimension Breakdown:\n{dims_txt}\n\n"
                f"Generated: {datetime.now(timezone.utc).isoformat()}\n"
            )
            msg = MIMEText(body)
            msg["Subject"] = subject
            msg["From"]    = cfg.get("from_addr", "pipeline@localhost")
            msg["To"]      = ", ".join(cfg.get("to_addrs", []))
            with smtplib.SMTP(cfg.get("smtp_host", "localhost"),
                              cfg.get("smtp_port", 587)) as server:
                server.starttls()
                server.login(cfg.get("username", ""), cfg.get("password", ""))
                server.sendmail(
                    cfg.get("from_addr", "pipeline@localhost"),
                    cfg.get("to_addrs", []),
                    msg.as_string()
                )
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning("Email send failed: %s", exc)

    def _alert_webhook(self, payload: dict) -> None:
        """POST the full alert payload to a generic HTTP webhook."""
        try:
            import urllib.request as _req  # pylint: disable=import-outside-toplevel
            data = json.dumps(payload, default=str).encode("utf-8")
            req  = _req.Request(self.webhook_url, data=data,  # type: ignore[arg-type]
                                headers={"Content-Type": "application/json"})
            with _req.urlopen(req, timeout=5):
                pass
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning("Webhook send failed: %s", exc)

    # ── Reporting helpers ─────────────────────────────────────────────────

    def alert_history(self, n: int = 50) -> list[dict]:
        """
        Return the last n alert records from the alert log file.

        Parameters
        ----------
        n : int   Maximum records to return (most recent first).

        Returns
        -------
        list[dict]
        """
        if not self.alert_log_file.exists():
            return []
        records = []
        for line in self.alert_log_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return list(reversed(records[-n:]))

    def summary(self) -> dict:
        """
        Return a summary of all alerts fired to date.

        Returns
        -------
        dict  {total_alerts, by_type, by_severity, most_recent}
        """
        history = self.alert_history(n=500)
        by_type: dict[str, int]     = {}
        by_sev:  dict[str, int]     = {}
        for rec in history:
            alert = rec.get("alert", {})
            t = alert.get("type", "UNKNOWN")
            s = alert.get("severity", "UNKNOWN")
            by_type[t] = by_type.get(t, 0) + 1
            by_sev[s]  = by_sev.get(s, 0) + 1
        return {
            "total_alerts": len(history),
            "by_type":      by_type,
            "by_severity":  by_sev,
            "most_recent":  history[0] if history else None,
        }
