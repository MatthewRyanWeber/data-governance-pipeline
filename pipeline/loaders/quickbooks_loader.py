"""
QuickBooks Online loader -- writes DataFrames to QBO via the REST API v3
with per-row create/update and rate-limit handling.

Layer 4 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py (class QuickBooksLoader).
1.1   2026-06-07   Added Layer 4 docstring convention.
"""

import time
import json
import logging
from typing import TYPE_CHECKING

from pipeline.loaders.base import BaseLoader

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class QuickBooksLoader(BaseLoader):
    """Load DataFrames into QuickBooks Online via the QBO REST API v3."""

    _PROD_BASE = "https://quickbooks.api.intuit.com"
    _SANDBOX_BASE = "https://sandbox-quickbooks.api.intuit.com"
    _TOKEN_URL = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer"

    _REQUIRED_FIELDS: dict[str, list[str]] = {
        "Customer": ["DisplayName"],
        "Vendor": ["DisplayName"],
        "Employee": ["GivenName", "FamilyName"],
        "Account": ["Name", "AccountType"],
        "Item": ["Name", "Type"],
        "Department": ["Name"],
        "Class": ["Name"],
    }

    def __init__(self, gov: "GovernanceLogger", dry_run: bool = False) -> None:
        super().__init__(gov, dry_run=dry_run)

    def _refresh_access_token(self, cfg: dict) -> str:
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
        return token_data["access_token"]

    def _headers(self, access_token: str) -> dict:
        return {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _base_url(self, cfg: dict) -> str:
        env = cfg.get("environment", "production").lower()
        base = self._SANDBOX_BASE if env == "sandbox" else self._PROD_BASE
        return f"{base}/v3/company/{cfg['realm_id']}"

    @staticmethod
    def _row_to_body(row, entity, sparse) -> dict:
        """Convert a flat DataFrame row into a QBO JSON body dict."""
        body: dict = {}

        for col, val in row.items():
            if sparse and (val is None or (isinstance(val, float)
                                           and val != val)):
                continue

            if isinstance(val, str):
                try:
                    val = json.loads(val)
                except (ValueError, TypeError):
                    pass

            parts = str(col).split("__")
            node = body
            for part in parts[:-1]:
                node = node.setdefault(part, {})
            node[parts[-1]] = val

        return body

    def _validate_row(self, body: dict, entity: str) -> list[str]:
        """Return a list of missing required fields."""
        required = self._REQUIRED_FIELDS.get(entity, [])
        return [f for f in required if not body.get(f)]

    def _post_entity(self, session, base_url, entity, body, timeout) -> dict:
        """POST a single QBO entity body via a shared session."""
        url = f"{base_url}/{entity.lower()}?minorversion=70"
        resp = session.post(url, json=body, timeout=timeout)
        if not resp.ok:
            raise RuntimeError(
                f"QuickBooks POST {entity} failed {resp.status_code}: "
                f"{resp.text[:400]}"
            )
        return resp.json()

    def load(self, df, cfg, table=None, if_exists="append", natural_keys=None):
        """Write df rows to QuickBooks Online as the specified entity type."""
        entity = cfg.get("entity", table or "Customer")
        if self._dry_run_guard(entity, len(df)):
            return
        self._validate_config(cfg, ["client_id", "client_secret", "refresh_token", "realm_id"])
        sparse = cfg.get("sparse", True)
        timeout = cfg.get("timeout", 30)
        delay = cfg.get("batch_delay", 0.1)
        custom_transform = cfg.get("row_transform")

        if if_exists == "replace":
            logger.warning(
                "[QBO] QuickBooks does not support bulk delete. "
                "'replace' mode will append/update rows only."
            )

        import requests

        token = self._refresh_access_token(cfg)
        headers = self._headers(token)
        base_url = self._base_url(cfg)

        created = updated = skipped = errors = 0

        logger.info("[QBO] Writing %s rows -> %s", f"{len(df):,}", entity)
        records = df.to_dict(orient="records")
        with requests.Session() as session:
            session.headers.update(headers)
            for idx, rec in enumerate(records):
                try:
                    if callable(custom_transform):
                        body = custom_transform(rec)
                    else:
                        body = self._row_to_body(rec, entity, sparse)

                    missing = self._validate_row(body, entity)
                    if missing:
                        logger.warning(
                            "[QBO] Row %s: skipping -- missing required "
                            "field(s): %s", idx, missing
                        )
                        skipped += 1
                        continue

                    had_id = bool(body.get("Id"))
                    self._post_entity(session, base_url, entity, body, timeout)

                    if had_id:
                        updated += 1
                    else:
                        created += 1

                    if delay > 0:
                        time.sleep(delay)

                except Exception as exc:
                    logger.error("[QBO] Row %s: %s", idx, exc)
                    errors += 1

        logger.info(
            "[QBO] %s: %d created  %d updated  %d skipped  %d errors",
            entity, created, updated, skipped, errors,
        )

        self.gov.load_complete(created + updated, entity)
        self.gov.destination_registered(
            "quickbooks",
            f"https://app.qbo.intuit.com/app/company/"
            f"{cfg.get('realm_id', '')}/{entity.lower()}",
            entity,
        )
        self.gov.transformation_applied("QBO_LOAD_COMPLETE", {
            "entity": entity,
            "created": created,
            "updated": updated,
            "skipped": skipped,
            "errors": errors,
        })
