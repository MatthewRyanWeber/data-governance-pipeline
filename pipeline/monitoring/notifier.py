"""
Email + Slack notification sender.

Sends pipeline completion/failure notifications with run statistics.

Layer 3 — imports from Layer 0 (constants), Layer 1 (governance_logger).
"""

import logging
import smtplib
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import TYPE_CHECKING

from pipeline.constants import HAS_REQUESTS, default_run_context

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class Notifier:
    """
    Sends email and/or Slack notifications on pipeline completion.

    Quick-start
    -----------
        from pipeline.monitoring import Notifier
        notifier = Notifier(gov, email_cfg={...}, slack_cfg={...})
        notifier.send(success=True, stats={"rows": 1000})
    """

    def __init__(self, gov: "GovernanceLogger", email_cfg=None, slack_cfg=None,
                 run_context=None) -> None:
        self.gov = gov
        self.email_cfg = email_cfg or {}
        self.slack_cfg = slack_cfg or {}
        self.run_context = run_context or default_run_context()

    def send(self, success: bool, stats: dict) -> None:
        if self.email_cfg:
            self._send_email(success, stats)
        if self.slack_cfg:
            self._send_slack(success, stats)

    def _build_subject(self, ok: bool) -> str:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
        status = "SUCCESS" if ok else "FAILED"
        return f"[Pipeline v4] {status} — {ts} UTC"

    def _build_html(self, ok: bool, stats: dict) -> str:
        from html import escape
        color = "#28a745" if ok else "#dc3545"
        status = "COMPLETED SUCCESSFULLY" if ok else "FAILED"
        rows = "".join(
            f"<tr><td><b>{escape(str(k))}</b></td><td>{escape(str(v))}</td></tr>"
            for k, v in stats.items()
        )
        return (
            f"<html><body><h2 style='color:{color}'>Pipeline {status}</h2>"
            f"<p><b>Pipeline ID:</b> {escape(str(self.run_context.pipeline_id))}</p>"
            f"<table border='1'>{rows}</table>"
            f"<p>Artefacts: {escape(str(self.gov.log_dir))}</p></body></html>"
        )

    def _send_email(self, ok: bool, stats: dict) -> None:
        cfg = self.email_cfg
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = self._build_subject(ok)
            msg["From"] = cfg["from_addr"]
            msg["To"] = ", ".join(cfg.get("to_addrs", [cfg["from_addr"]]))
            msg.attach(MIMEText(self._build_html(ok, stats), "html"))
            port = int(cfg.get("smtp_port", 587))
            if port == 465:
                with smtplib.SMTP_SSL(cfg["smtp_host"], port) as s:
                    s.login(cfg["smtp_user"], cfg["smtp_password"])
                    s.send_message(msg)
            else:
                with smtplib.SMTP(cfg["smtp_host"], port) as s:
                    s.ehlo()
                    s.starttls()
                    s.login(cfg["smtp_user"], cfg["smtp_password"])
                    s.send_message(msg)
            self.gov.notification_sent("email", "SUCCESS")
            logger.info("[NOTIFY] Email → %s", msg["To"])
        except Exception as exc:
            self.gov.notification_sent("email", "FAILED", str(exc))
            logger.error("[NOTIFY] Email failed: %s", exc)

    def _send_slack(self, ok: bool, stats: dict) -> None:
        if not HAS_REQUESTS:
            self.gov.notification_sent("slack", "FAILED", "requests not installed")
            return
        import requests
        try:
            resp = requests.post(self.slack_cfg["webhook_url"], timeout=10, json={
                "text": f"{'SUCCESS' if ok else 'FAILED'} Pipeline",
                "attachments": [{
                    "color": "#28a745" if ok else "#dc3545",
                    "text": (
                        f"*ID:* {self.run_context.pipeline_id}\n"
                        + "\n".join(f"*{k}*: {v}" for k, v in stats.items())
                    ),
                    "mrkdwn_in": ["text"],
                }],
            })
            resp.raise_for_status()
            self.gov.notification_sent("slack", "SUCCESS")
            logger.info("[NOTIFY] Slack message sent.")
        except Exception as exc:
            self.gov.notification_sent("slack", "FAILED", str(exc))
            logger.error("[NOTIFY] Slack failed: %s", exc)
