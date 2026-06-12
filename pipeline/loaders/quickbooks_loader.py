"""
QuickBooks Online loader -- writes DataFrames to QBO via the REST API v3
using the $batch endpoint (30 operations per request) with SyncToken-aware
sparse updates and rate-limit handling.

Layer 4 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py (class QuickBooksLoader).
1.1   2026-06-07   Added Layer 4 docstring convention.
1.2   2026-06-11   Rewrote the write path to use QBO's $batch endpoint
                   (30 ops per request) instead of one POST + 0.1s sleep per
                   row.  Updates now fetch the entity's SyncToken and send
                   sparse updates (previously every update was rejected).
                   Only true successes are reported to gov.load_complete;
                   per-item faults are logged as errors.
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

    # QBO's $batch endpoint accepts at most 30 operations per request
    _BATCH_SIZE = 30

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
        return str(token_data["access_token"])

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

    def _fetch_sync_token(self, session, base_url, entity, entity_id, timeout) -> str:
        """
        Fetch the current SyncToken for an existing entity.

        QBO rejects every update that lacks the entity's current SyncToken,
        so an update without it can never succeed.
        """
        url = f"{base_url}/{entity.lower()}/{entity_id}?minorversion=70"
        resp = session.get(url, timeout=timeout)
        if not resp.ok:
            raise RuntimeError(
                f"QuickBooks GET {entity}/{entity_id} for SyncToken failed "
                f"{resp.status_code}: {resp.text[:300]}"
            )
        payload = resp.json()
        sync_token = payload.get(entity, {}).get("SyncToken")
        if sync_token is None:
            raise RuntimeError(
                f"QuickBooks response for {entity}/{entity_id} did not "
                f"contain a SyncToken: {str(payload)[:300]}"
            )
        return str(sync_token)

    def _post_batch(self, session, base_url, entity, items, timeout) -> tuple[int, int, int]:
        """
        POST up to _BATCH_SIZE operations to QBO's $batch endpoint.

        Returns (created, updated, errors) based on per-item responses —
        a 200 on the envelope does not mean every item succeeded.
        """
        url = f"{base_url}/batch?minorversion=70"
        request_body = {
            "BatchItemRequest": [
                {
                    "bId": str(item["bId"]),
                    "operation": item["operation"],
                    entity: item["body"],
                }
                for item in items
            ],
        }
        resp = session.post(url, json=request_body, timeout=timeout)
        if not resp.ok:
            raise RuntimeError(
                f"QuickBooks $batch POST failed {resp.status_code}: "
                f"{resp.text[:400]}"
            )

        operations_by_bid = {str(item["bId"]): item["operation"] for item in items}
        created = updated = errors = 0
        responses = resp.json().get("BatchItemResponse", [])
        answered_bids = set()

        for item_response in responses:
            bid = str(item_response.get("bId", ""))
            answered_bids.add(bid)
            fault = item_response.get("Fault")
            if fault:
                errors += 1
                logger.error(
                    "[QUICKBOOKS] Batch item %s FAILED: %s",
                    bid, json.dumps(fault)[:400],
                )
                continue
            if operations_by_bid.get(bid) == "update":
                updated += 1
            else:
                created += 1

        # Items QBO never answered are failures, not successes
        unanswered = set(operations_by_bid) - answered_bids
        if unanswered:
            errors += len(unanswered)
            logger.error(
                "[QUICKBOOKS] %d batch item(s) missing from the response: %s",
                len(unanswered), sorted(unanswered),
            )

        return created, updated, errors

    def load(self, df, cfg, table=None, if_exists="append", natural_keys=None) -> int:
        """
        Write df rows to QuickBooks Online as the specified entity type.

        Rows are sent through the $batch endpoint, 30 operations per
        request.  Rows carrying an Id become sparse updates with a freshly
        fetched SyncToken; all other rows are creates.  Returns the number
        of rows QBO actually accepted.
        """
        entity = cfg.get("entity", table or "Customer")
        if self._dry_run_guard(entity, len(df)):
            return 0
        self._validate_config(cfg, ["client_id", "client_secret", "refresh_token", "realm_id"])
        sparse = cfg.get("sparse", True)
        timeout = cfg.get("timeout", 30)
        delay = cfg.get("batch_delay", 0.1)
        custom_transform = cfg.get("row_transform")

        if if_exists == "replace":
            logger.warning(
                "[QUICKBOOKS] QuickBooks does not support bulk delete. "
                "'replace' mode will append/update rows only."
            )

        import requests

        token = self._refresh_access_token(cfg)
        headers = self._headers(token)
        base_url = self._base_url(cfg)

        created = updated = skipped = errors = 0

        logger.info("[QUICKBOOKS] Writing %s rows -> %s", f"{len(df):,}", entity)
        records = df.to_dict(orient="records")
        with requests.Session() as session:
            session.headers.update(headers)

            pending: list[dict] = []
            for idx, rec in enumerate(records):
                try:
                    if callable(custom_transform):
                        body = custom_transform(rec)
                    else:
                        body = self._row_to_body(rec, entity, sparse)

                    missing = self._validate_row(body, entity)
                    if missing:
                        logger.warning(
                            "[QUICKBOOKS] Row %s: skipping -- missing required "
                            "field(s): %s", idx, missing
                        )
                        skipped += 1
                        continue

                    if body.get("Id"):
                        body["SyncToken"] = self._fetch_sync_token(
                            session, base_url, entity, body["Id"], timeout,
                        )
                        if sparse:
                            body["sparse"] = True
                        operation = "update"
                    else:
                        operation = "create"

                    pending.append({
                        "bId": idx,
                        "operation": operation,
                        "body": body,
                    })
                except Exception as exc:
                    logger.error("[QUICKBOOKS] Row %s: %s", idx, exc)
                    errors += 1

            for start in range(0, len(pending), self._BATCH_SIZE):
                chunk = pending[start: start + self._BATCH_SIZE]
                try:
                    chunk_created, chunk_updated, chunk_errors = self._post_batch(
                        session, base_url, entity, chunk, timeout,
                    )
                    created += chunk_created
                    updated += chunk_updated
                    errors += chunk_errors
                except Exception as exc:
                    logger.error(
                        "[QUICKBOOKS] Batch of %d item(s) FAILED: %s",
                        len(chunk), exc,
                    )
                    errors += len(chunk)

                # Pause between batch requests, not per row, to respect
                # QBO rate limits without serialising every record
                if delay > 0 and start + self._BATCH_SIZE < len(pending):
                    time.sleep(delay)

        if errors:
            logger.error(
                "[QUICKBOOKS] %s: %d row(s) FAILED to load (%d created, "
                "%d updated, %d skipped).",
                entity, errors, created, updated, skipped,
            )
        logger.info(
            "[QUICKBOOKS] %s: %d created  %d updated  %d skipped  %d errors",
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
        return created + updated
