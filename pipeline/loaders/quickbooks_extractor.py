"""
QuickBooks Online extractor -- pulls data from QBO REST API v3 into
pandas DataFrames with OAuth2 refresh-token flow and auto-pagination.

Layer 4 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py (class QuickBooksExtractor).
1.1   2026-06-07   Added Layer 4 docstring convention.
"""

import json
import logging
import re
from typing import TYPE_CHECKING

import pandas as pd

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class QuickBooksExtractor:
    """Extract data from QuickBooks Online (QBO) into pandas DataFrames."""

    _PROD_BASE = "https://quickbooks.api.intuit.com"
    _SANDBOX_BASE = "https://sandbox-quickbooks.api.intuit.com"
    _TOKEN_URL = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer"

    _DATE_FIELDS: dict[str, str] = {
        "Invoice": "TxnDate",
        "Bill": "TxnDate",
        "Payment": "TxnDate",
        "CreditMemo": "TxnDate",
        "Estimate": "TxnDate",
        "PurchaseOrder": "TxnDate",
        "SalesReceipt": "TxnDate",
        "Transfer": "TxnDate",
        "JournalEntry": "TxnDate",
    }

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov

    def _refresh_access_token(self, cfg: dict) -> str:
        """Exchange a refresh token for a new access token."""
        import requests
        import base64
        credentials = base64.b64encode(
            f"{cfg['client_id']}:{cfg['client_secret']}".encode()
        ).decode()
        resp = requests.post(
            self._TOKEN_URL,
            headers={
                "Authorization": f"Basic {credentials}",
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data={
                "grant_type": "refresh_token",
                "refresh_token": cfg["refresh_token"],
            },
            timeout=cfg.get("timeout", 30),
        )
        if not resp.ok:
            raise RuntimeError(
                f"QuickBooks token refresh failed {resp.status_code}: "
                f"{resp.text[:300]}"
            )
        token_data = resp.json()
        if "refresh_token" in token_data:
            cfg["refresh_token"] = token_data["refresh_token"]
        return str(token_data["access_token"])

    def _headers(self, access_token: str) -> dict:
        return {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        }

    def _base_url(self, cfg: dict) -> str:
        env = cfg.get("environment", "production").lower()
        base = self._SANDBOX_BASE if env == "sandbox" else self._PROD_BASE
        return f"{base}/v3/company/{cfg['realm_id']}"

    _DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2})?$")

    def _build_query(self, entity, cfg, start, page_size) -> str:
        """Build a QBO SQL-like query string with optional date filters."""
        where_parts: list[str] = []

        date_field = cfg.get("date_field") or self._DATE_FIELDS.get(
            entity, "MetaData.LastUpdatedTime"
        )
        if cfg.get("date_from"):
            if not self._DATE_RE.match(cfg["date_from"]):
                raise ValueError(f"Invalid date_from format: {cfg['date_from']!r}")
            where_parts.append(f"{date_field} >= '{cfg['date_from']}'")
        if cfg.get("date_to"):
            if not self._DATE_RE.match(cfg["date_to"]):
                raise ValueError(f"Invalid date_to format: {cfg['date_to']!r}")
            where_parts.append(f"{date_field} <= '{cfg['date_to']}'")
        if cfg.get("extra_where"):
            where_parts.append(cfg["extra_where"])

        where_clause = (
            f" WHERE {' AND '.join(where_parts)}" if where_parts else ""
        )
        return (
            f"SELECT * FROM {entity}{where_clause}"
            f" STARTPOSITION {start} MAXRESULTS {page_size}"
        )

    @staticmethod
    def _flatten_qbo_record(record: dict, entity: str) -> dict:
        """Flatten a single QBO JSON record into a plain dict."""
        flat: dict = {}

        def _walk(node: object, prefix: str) -> None:
            if isinstance(node, dict):
                for k, v in node.items():
                    _walk(v, f"{prefix}__{k}" if prefix else k)
            elif isinstance(node, list):
                flat[prefix] = json.dumps(node)
            else:
                flat[prefix] = node

        _walk(record, "")
        return flat

    def extract(self, cfg: dict) -> "pd.DataFrame":
        """
        Extract all records for the configured entity type from QBO.

        Returns a DataFrame with one row per QBO record, columns flattened.
        """
        import requests

        entity = cfg.get("entity", "Customer")
        page_size = min(cfg.get("page_size", 1_000), 1_000)
        timeout = cfg.get("timeout", 30)
        base_url = self._base_url(cfg)
        token = self._refresh_access_token(cfg)
        headers = self._headers(token)

        all_records: list[dict] = []
        start = 1

        logger.info("[QUICKBOOKS] Extracting %s from realm %s",
                    entity, cfg['realm_id'])
        with requests.Session() as session:
            session.headers.update(headers)
            while True:
                query = self._build_query(entity, cfg, start, page_size)
                resp = session.get(
                    f"{base_url}/query",
                    params={"query": query, "minorversion": "70"},
                    timeout=timeout,
                )
                if not resp.ok:
                    raise RuntimeError(
                        f"QuickBooks API error {resp.status_code}: "
                        f"{resp.text[:400]}"
                    )
                payload = resp.json()
                qr = payload.get("QueryResponse", {})
                entities = qr.get(entity, [])

                if not entities:
                    break

                for record in entities:
                    all_records.append(
                        self._flatten_qbo_record(record, entity)
                    )

                total_count = qr.get("totalCount", len(entities))
                logger.info("[QUICKBOOKS]   page start=%d  fetched=%d  total=%s",
                            start, len(entities), total_count)

                if len(entities) < page_size:
                    break
                start += page_size

        df = pd.DataFrame(all_records) if all_records else pd.DataFrame()
        logger.info("[QUICKBOOKS] %s %s records extracted", f"{len(df):,}", entity)

        self.gov.transformation_applied("QBO_EXTRACT_COMPLETE", {
            "entity": entity,
            "realm_id": cfg.get("realm_id"),
            "rows": len(df),
        })
        return df
