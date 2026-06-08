"""
Generic REST API extractor — pulls data from HTTP APIs with pagination.

Supports offset, cursor, and link-header pagination strategies, configurable
authentication (Bearer, Basic, API key), rate limiting, and retry logic.

Layer 3 — imports from Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-08   Initial release.
"""

import logging
import time
from typing import TYPE_CHECKING, Any, Iterator

if TYPE_CHECKING:
    import pandas as pd
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class RESTExtractor:
    """
    Pulls data from HTTP REST APIs into DataFrames.

    Quick-start
    -----------
        from pipeline.extractors import RESTExtractor
        ext = RESTExtractor(gov)
        df = ext.extract({
            "url": "https://api.example.com/v1/users",
            "auth": {"type": "bearer", "token": "sk-..."},
            "pagination": {"type": "offset", "limit_param": "limit", "offset_param": "offset", "page_size": 100},
            "data_path": "results",
        })
    """

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov

    @staticmethod
    def _build_session(auth: dict | None):
        """Create a requests.Session with auth headers configured."""
        import requests

        session = requests.Session()
        if not auth:
            return session

        auth_type = auth.get("type", "").lower()

        if auth_type == "bearer":
            session.headers["Authorization"] = f"Bearer {auth['token']}"
        elif auth_type == "basic":
            session.auth = (auth["username"], auth["password"])
        elif auth_type == "api_key":
            key_name = auth.get("header", "X-API-Key")
            session.headers[key_name] = auth["key"]
        elif auth_type == "custom_header":
            for header_name, header_value in auth.get("headers", {}).items():
                session.headers[header_name] = header_value

        return session

    @staticmethod
    def _extract_data(response_json: Any, data_path: str | None) -> list[dict]:
        """Navigate a dotted path (e.g. 'data.results') to find the records array."""
        if data_path is None:
            if isinstance(response_json, list):
                return response_json
            return [response_json]

        node = response_json
        for key in data_path.split("."):
            if isinstance(node, dict):
                node = node.get(key, [])
            else:
                return []

        if isinstance(node, list):
            return node
        return [node]

    def _pages(self, cfg: dict) -> Iterator[list[dict]]:
        """Yield pages of records from the API."""
        url = cfg["url"]
        auth = cfg.get("auth")
        pagination = cfg.get("pagination", {})
        data_path = cfg.get("data_path")
        params = dict(cfg.get("params", {}))
        timeout = cfg.get("timeout", 30)
        max_pages = cfg.get("max_pages", 1000)
        rate_limit_delay = cfg.get("rate_limit_delay", 0.1)
        max_retries = cfg.get("max_retries", 3)

        pag_type = pagination.get("type", "none").lower()

        session = self._build_session(auth)
        page_count = 0

        try:
            if pag_type == "offset":
                page_size = pagination.get("page_size", 100)
                limit_param = pagination.get("limit_param", "limit")
                offset_param = pagination.get("offset_param", "offset")
                offset = pagination.get("start_offset", 0)

                while page_count < max_pages:
                    params[limit_param] = page_size
                    params[offset_param] = offset

                    data = self._fetch_with_retry(
                        session, url, params, timeout, max_retries,
                    )
                    records = self._extract_data(data, data_path)

                    if not records:
                        break

                    yield records
                    page_count += 1

                    if len(records) < page_size:
                        break

                    offset += page_size
                    if rate_limit_delay > 0:
                        time.sleep(rate_limit_delay)

            elif pag_type == "cursor":
                cursor_param = pagination.get("cursor_param", "cursor")
                cursor_path = pagination.get("cursor_path", "next_cursor")
                page_size = pagination.get("page_size", 100)
                limit_param = pagination.get("limit_param", "limit")
                cursor = pagination.get("initial_cursor")

                while page_count < max_pages:
                    if page_size:
                        params[limit_param] = page_size
                    if cursor:
                        params[cursor_param] = cursor

                    data = self._fetch_with_retry(
                        session, url, params, timeout, max_retries,
                    )
                    records = self._extract_data(data, data_path)

                    if not records:
                        break

                    yield records
                    page_count += 1

                    cursor = self._extract_data(data, cursor_path)
                    if isinstance(cursor, list):
                        cursor = cursor[0] if cursor else None
                    if not cursor:
                        break

                    if rate_limit_delay > 0:
                        time.sleep(rate_limit_delay)

            elif pag_type == "link_header":
                next_url = url
                page_size = pagination.get("page_size", 100)
                limit_param = pagination.get("limit_param", "per_page")

                while next_url and page_count < max_pages:
                    if page_size:
                        params[limit_param] = page_size

                    resp = self._raw_fetch_with_retry(
                        session, next_url, params, timeout, max_retries,
                    )
                    data = resp.json()
                    records = self._extract_data(data, data_path)

                    if not records:
                        break

                    yield records
                    page_count += 1

                    link_header = resp.headers.get("Link", "")
                    next_url = self._parse_link_next(link_header)
                    params = {}

                    if rate_limit_delay > 0:
                        time.sleep(rate_limit_delay)

            else:
                data = self._fetch_with_retry(
                    session, url, params, timeout, max_retries,
                )
                records = self._extract_data(data, data_path)
                if records:
                    yield records
                page_count = 1
        finally:
            session.close()

        logger.info("[REST_EXTRACT] Fetched %d page(s) from %s", page_count, url)

    def _fetch_with_retry(
        self, session, url: str, params: dict, timeout: int, max_retries: int,
    ) -> Any:
        """GET with exponential backoff retry."""
        resp = self._raw_fetch_with_retry(session, url, params, timeout, max_retries)
        return resp.json()

    def _raw_fetch_with_retry(self, session, url, params, timeout, max_retries):
        """GET with retry, returning the raw Response object."""
        last_exc = None
        for attempt in range(max_retries):
            try:
                resp = session.get(url, params=params, timeout=timeout)
                if resp.status_code == 429:
                    raw_retry = resp.headers.get("Retry-After", str(2 ** attempt))
                    try:
                        retry_after = int(raw_retry)
                    except ValueError:
                        retry_after = 2 ** attempt
                    logger.warning(
                        "[REST_EXTRACT] Rate limited (429) — waiting %ds", retry_after,
                    )
                    time.sleep(retry_after)
                    continue
                resp.raise_for_status()
                return resp
            except Exception as exc:
                last_exc = exc
                wait = 2 ** attempt
                logger.warning(
                    "[REST_EXTRACT] Attempt %d/%d failed: %s — retrying in %ds",
                    attempt + 1, max_retries, exc, wait,
                )
                self.gov.retry_attempt(attempt + 1, max_retries, wait, exc)
                time.sleep(wait)

        raise RuntimeError(
            f"REST extraction failed after {max_retries} attempts: {last_exc}"
        ) from last_exc

    @staticmethod
    def _parse_link_next(link_header: str) -> str | None:
        """Parse the 'next' URL from a RFC 5988 Link header."""
        for part in link_header.split(","):
            if 'rel="next"' in part:
                url_part = part.split(";")[0].strip()
                if url_part.startswith("<") and url_part.endswith(">"):
                    return url_part[1:-1]
        return None

    def extract(self, cfg: dict) -> "pd.DataFrame":
        """
        Fetch all pages and return a single DataFrame.

        Config keys:
            url: str            — API endpoint URL (required)
            auth: dict | None   — {type: bearer|basic|api_key|custom_header, ...}
            pagination: dict    — {type: offset|cursor|link_header|none, ...}
            data_path: str      — dotted path to records array in response JSON
            params: dict        — extra query parameters
            timeout: int        — request timeout in seconds (default 30)
            max_pages: int      — safety limit on pagination (default 1000)
            rate_limit_delay: float — seconds between requests (default 0.1)
            flatten: bool       — json_normalize nested records (default True)
        """
        import pandas as pd

        self.gov.extract_event("REST_EXTRACT_START", {
            "url": cfg["url"],
            "pagination": cfg.get("pagination", {}).get("type", "none"),
        })

        all_records: list[dict] = []
        for page in self._pages(cfg):
            all_records.extend(page)

        if not all_records:
            logger.warning("[REST_EXTRACT] No records returned from %s", cfg["url"])
            return pd.DataFrame()

        if cfg.get("flatten", True):
            df = pd.json_normalize(all_records, sep="__")
        else:
            df = pd.DataFrame(all_records)

        self.gov.source_registered(cfg["url"], "rest_api", len(df), len(df.columns))
        self.gov.extract_event("REST_EXTRACT_COMPLETE", {
            "url": cfg["url"],
            "rows": len(df),
            "columns": list(df.columns),
        })
        logger.info(
            "[REST_EXTRACT] %s → %d rows, %d columns",
            cfg["url"], len(df), len(df.columns),
        )
        return df

    def pages(self, cfg: dict) -> Iterator["pd.DataFrame"]:
        """Yield one DataFrame per API page for streaming processing."""
        import pandas as pd

        flatten = cfg.get("flatten", True)

        for i, records in enumerate(self._pages(cfg)):
            if flatten:
                df = pd.json_normalize(records, sep="__")
            else:
                df = pd.DataFrame(records)
            logger.info("[REST_EXTRACT] Page %d: %d rows", i, len(df))
            yield df
