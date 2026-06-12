"""
Shared helper functions and base class for loader modules.

Provides SQL-injection-safe identifier validation, float-vector validation,
DataFrame column name validation, and a BaseLoader class with dry_run support,
config validation, and engine lifecycle management used by all loader subclasses.

Note: loaders resolved through pipeline.loaders.resolve_loader() get
validate_column_names() applied to every load() call automatically — the
dispatch installs a guard wrapper, so individual loaders never call it
themselves.  See pipeline/loaders/__init__.py:_install_column_name_guard.

Revision history
────────────────
1.0   2026-06-07   Initial extraction from pipeline_v3.py.
1.1   2026-06-08   Added BaseLoader, validate_column_names.
1.2   2026-06-08   Added _engine_scope context manager.
1.3   2026-06-09   Added opt-in circuit breaker helpers.
1.4   2026-06-09   Added _retry_with_backoff helper with circuit breaker integration.
1.5   2026-06-09   Added field-level encryption helpers for transparent encrypt-on-load.
1.6   2026-06-11   Added backtick to _BAD_CHARS_RE so column names cannot break
                   out of backtick-quoted DDL (BigQuery, Databricks, ClickHouse).
1.7   2026-06-12   Added _require_upsert_keys shared guard; dry-run docstring examples return 0.
"""

import contextlib
import math
import re
import logging
from typing import TYPE_CHECKING

from pipeline.exceptions import CircuitOpenError, ConfigValidationError

if TYPE_CHECKING:
    import pandas as pd
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)

# Backtick included: several loaders quote identifiers with ` (BigQuery,
# Databricks, ClickHouse), so a backtick in a column name would break out
# of the quoting and allow SQL injection through DDL/MERGE strings.
_BAD_CHARS_RE = re.compile(r"[;'\"`\-/\\*]")


def validate_sql_identifier(name: str, label: str = "identifier") -> str:
    """
    Validate a SQL identifier (table name, column name, index name) to prevent
    SQL injection.  Only allows alphanumeric characters, underscores, and dots
    (for schema.table notation).

    Raises ValueError if the name contains any disallowed characters.
    Returns the name unchanged if valid.
    """
    if not name:
        raise ValueError(f"SQL {label} must not be empty.")
    if not re.fullmatch(r"[A-Za-z_][\w.]*", name):
        raise ValueError(
            f"SQL {label} '{name}' contains disallowed characters. "
            "Only letters, digits, underscores, and dots are allowed."
        )
    return name


def validate_float_vector(vec: list, label: str = "query_vector") -> list:
    """
    Validate that every element of a vector is a finite float.
    Prevents SQL injection via NaN, inf, or non-numeric values in
    concatenated vector literals.

    Raises ValueError on the first invalid element.
    Returns a list of Python floats.
    """
    result = []
    for i, v in enumerate(vec):
        try:
            f = float(v)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"{label}[{i}] is not a valid float: {v!r}"
            ) from exc
        if not math.isfinite(f):
            raise ValueError(
                f"{label}[{i}] is not finite: {f!r}. "
                "NaN and inf are not valid vector components."
            )
        result.append(f)
    return result


def validate_column_names(df: "pd.DataFrame", label: str = "DataFrame") -> None:
    """
    Validate that DataFrame column names are safe for SQL DDL construction.

    Rejects columns containing SQL-injection characters (semicolons, quotes,
    comment markers, etc.).  Raises ValueError on the first invalid column.
    """
    for col in df.columns:
        col_str = str(col)
        if _BAD_CHARS_RE.search(col_str):
            raise ValueError(
                f"{label} column name {col_str!r} contains disallowed "
                "characters for SQL DDL construction."
            )


class BaseLoader:
    """
    Abstract base class for all pipeline loaders.

    Provides dry_run support and config validation so subclasses only
    need to implement their specific load/connect logic.

    Subclasses call super().__init__(gov, dry_run) and use:
        self._validate_config(cfg, ["host", "user", "password"])
        if self._dry_run_guard(table, len(df)): return 0
    """

    def __init__(self, gov: "GovernanceLogger", dry_run: bool = False) -> None:
        self.gov = gov
        self.dry_run = dry_run

    def _validate_config(self, cfg: dict, required_keys: list[str]) -> None:
        """
        Validate that all required keys are present and non-empty in cfg.

        Supports 'key1|key2' syntax: at least one alternative must be present.
        Raises ConfigValidationError on missing keys.
        """
        missing = []
        for req in required_keys:
            if "|" in req:
                alternatives = req.split("|")
                if not any(cfg.get(alt) for alt in alternatives):
                    missing.append(f"one of ({', '.join(alternatives)})")
            else:
                if not cfg.get(req):
                    missing.append(req)

        if missing:
            db_type = getattr(self, "_db_type", self.__class__.__name__)
            raise ConfigValidationError(
                db_type=str(db_type),
                missing_keys=missing,
            )

    def _require_upsert_keys(self, if_exists: str, natural_keys) -> None:
        """
        Reject if_exists='upsert' with no natural_keys.

        Without keys an upsert silently degrades to append — duplicated
        data with no warning.  Loaders whose backend upserts by a native
        id (Qdrant, Chroma, ...) simply don't call this.
        """
        if if_exists == "upsert" and not natural_keys:
            raise ValueError(
                f"{self.__class__.__name__}: if_exists='upsert' requires "
                f"natural_keys — without them the load would silently "
                f"append duplicates."
            )

    def _dry_run_guard(self, table: str, row_count: int) -> bool:
        """
        Log what would happen and return True if dry_run is active.

        Callers should short-circuit: ``if self._dry_run_guard(...): return 0``
        (0, not bare return — load() returns the row count in every path)
        """
        if not self.dry_run:
            return False
        logger.info(
            "[DRY RUN] Would write %s rows to '%s' via %s — skipping.",
            f"{row_count:,}", table, self.__class__.__name__,
        )
        return True

    @contextlib.contextmanager
    def _engine_scope(self, cfg: dict):
        """
        Create a SQLAlchemy engine, yield it, and guarantee disposal.

        Subclasses that define ``_engine(cfg)`` get automatic lifecycle
        management::

            with self._engine_scope(cfg) as engine:
                df.to_sql(table, engine, ...)
        """
        engine = self._engine(cfg)  # type: ignore[attr-defined]
        try:
            yield engine
        finally:
            engine.dispose()

    # ── Circuit breaker helpers (opt-in) ───────────────────────────────

    def _init_circuit_breaker(
        self,
        name: str,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
        success_threshold: int = 3,
    ) -> None:
        from pipeline.circuit_breaker import CircuitBreaker
        self._circuit_breaker = CircuitBreaker(
            name,
            failure_threshold=failure_threshold,
            recovery_timeout=recovery_timeout,
            success_threshold=success_threshold,
        )

    def _check_circuit(self) -> None:
        cb = getattr(self, "_circuit_breaker", None)
        if cb is not None and not cb.allow_request():
            raise CircuitOpenError(cb.name)

    def _record_circuit_success(self) -> None:
        cb = getattr(self, "_circuit_breaker", None)
        if cb is not None:
            cb.record_success()

    def _record_circuit_failure(self) -> None:
        cb = getattr(self, "_circuit_breaker", None)
        if cb is not None:
            cb.record_failure()

    # ── Retry with exponential backoff (opt-in) ──────────────────────────

    def _retry_with_backoff(
        self,
        fn,
        max_retries: int = 3,
        base_delay: float = 1.0,
    ):
        """
        Call fn() with exponential backoff, circuit breaker integration,
        and governance logging per retry.

        On success: records circuit success, returns result.
        On exhaustion: records circuit failure, raises last exception.
        """
        import time

        self._check_circuit()
        last_exc = None
        for attempt in range(max_retries):
            try:
                result = fn()
                self._record_circuit_success()
                return result
            except Exception as exc:
                last_exc = exc
                if attempt < max_retries - 1:
                    wait = base_delay * (2 ** attempt)
                    self.gov.retry_attempt(attempt + 1, max_retries, wait, exc)
                    logger.warning(
                        "Retry %d/%d after %.1fs: %s",
                        attempt + 1, max_retries, wait, exc,
                    )
                    time.sleep(wait)
        self._record_circuit_failure()
        raise last_exc  # type: ignore[misc]

    # ── Field-level encryption (opt-in) ──────────────────────────────────

    def _encrypt_columns(self, df, columns: list[str], key: str):
        """Encrypt specified columns using Fernet AES-256-CBC."""
        from pipeline.privacy.column_encryptor import ColumnEncryptor
        enc = ColumnEncryptor(self.gov, key)
        return enc.encrypt(df, columns)

    def _decrypt_columns(self, df, columns: list[str], key: str):
        """Decrypt previously-encrypted columns."""
        from pipeline.privacy.column_encryptor import ColumnEncryptor
        enc = ColumnEncryptor(self.gov, key)
        return enc.decrypt(df, columns)

    def _apply_load_encryption(self, df, cfg: dict):
        """
        Encrypt columns before load if cfg specifies encrypt_columns + encryption_key.

        Returns df unchanged if encryption is not configured.
        """
        columns = cfg.get("encrypt_columns")
        key = cfg.get("encryption_key")
        if not columns or not key:
            return df
        return self._encrypt_columns(df, columns, key)
