"""
SAP Datasphere loader -- uploads DataFrames to SAP Datasphere (formerly
SAP Data Warehouse Cloud) via the official OData v4 REST API.

Layer 4 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py (class DatasphereLoader).
1.1   2026-06-07   Added Layer 4 docstring convention.
"""

import logging
from typing import TYPE_CHECKING

from pipeline.constants import HAS_DATASPHERE
from pipeline.loaders.base import BaseLoader

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class DatasphereLoader(BaseLoader):
    """SAP Datasphere loader via OData v4 REST API with OAuth2."""

    _ODATA_PATH = "/api/v1/dwc/catalog/spaces/{space}/assets/{table}/data"

    def __init__(self, gov: "GovernanceLogger", dry_run: bool = False) -> None:
        super().__init__(gov, dry_run=dry_run)
        if not HAS_DATASPHERE:
            raise RuntimeError(
                "requests not installed.  Run: pip install requests"
            )

    def _get_token(self, cfg: dict) -> str:
        """Fetch an OAuth2 client-credentials bearer token."""
        if cfg.get("token"):
            return cfg["token"]
        import requests
        resp = requests.post(
            cfg["token_url"],
            data={
                "grant_type": "client_credentials",
                "client_id": cfg["client_id"],
                "client_secret": cfg["client_secret"],
            },
            timeout=cfg.get("timeout", 30),
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

    def _endpoint(self, cfg: dict) -> str:
        base = cfg["tenant_url"].rstrip("/")
        path = self._ODATA_PATH.format(
            space=cfg["space"],
            table=cfg.get("table", ""),
        )
        return base + path

    def _headers(self, token: str) -> dict:
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _truncate(self, cfg: dict, token: str) -> None:
        """Call the Datasphere truncate action to clear the local table."""
        import requests
        base = cfg["tenant_url"].rstrip("/")
        url = (f"{base}/api/v1/dwc/catalog/spaces/{cfg['space']}"
               f"/assets/{cfg.get('table', '')}/data/$truncate")
        resp = requests.post(url, headers=self._headers(token),
                             timeout=cfg.get("timeout", 30))
        resp.raise_for_status()

    def _patch_batch(self, url, headers, rows, timeout):
        """POST a batch of rows as JSON to the OData endpoint."""
        import requests
        payload = {"value": rows}
        resp = requests.patch(url, headers=headers,
                              json=payload, timeout=timeout)
        if not resp.ok:
            raise RuntimeError(
                f"Datasphere OData error {resp.status_code}: {resp.text[:400]}"
            )

    def load(self, df, cfg, table=None, if_exists="append", natural_keys=None):
        """Upload df to a SAP Datasphere Local Table via OData v4."""
        tbl = cfg.get("table", table or "")
        if self._dry_run_guard(tbl or "datasphere_table", len(df)):
            return
        self._validate_config(cfg, ["tenant_url", "token|token_url"])
        timeout = cfg.get("timeout", 30)
        batch = cfg.get("batch_size", 1_000)

        token = self._get_token(cfg)
        url = self._endpoint({**cfg, "table": tbl})
        headers = self._headers(token)

        if if_exists == "replace":
            self._truncate({**cfg, "table": tbl}, token)

        records = df.where(df.notna(), other=None).to_dict(orient="records")

        for i in range(0, len(records), batch):
            self._patch_batch(url, headers, records[i: i + batch], timeout)

        self.gov.load_complete(len(df), tbl)
        self.gov.destination_registered(
            "datasphere",
            f"{cfg['tenant_url']}/space/{cfg.get('space', '')}/{tbl}",
            tbl,
        )
        self.gov.transformation_applied("DATASPHERE_LOAD_COMPLETE", {
            "space": cfg.get("space"), "table": tbl, "rows": len(df),
            "mode": if_exists,
        })
