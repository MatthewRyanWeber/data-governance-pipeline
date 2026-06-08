"""
GDPR Article 17 Right-to-Erasure handler.

Locates and erases (hard delete or nullify) all records for a given
data subject across the target database. Subject IDs are hashed before
being stored in the audit trail.

Layer 3 — imports from Layer 1 (governance_logger).
"""

import hashlib
import logging
import re
from typing import TYPE_CHECKING
from urllib.parse import quote_plus as _qp

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)

_SAFE_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")


def _validate_ident(name: str, label: str) -> None:
    if not _SAFE_IDENT.match(name):
        raise ValueError(f"Unsafe SQL identifier for {label}: {name!r}")


class ErasureHandler:
    """
    Executes GDPR Art. 17 erasure requests.

    Quick-start
    -----------
        from pipeline.privacy import ErasureHandler
        handler = ErasureHandler(gov)
        handler.execute(
            subject_id="alice@example.com", subject_col="email",
            db_type="sqlite", db_cfg={"db_name": "output"},
            table="employees", mode="delete",
        )
    """

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov

    def erase(self, subject_id: str, table: str, db_type: str, db_cfg: dict,
              id_column: str = "id", mode: str = "delete",
              pii_cols: list[str] | None = None) -> int:
        return self.execute(
            subject_id=subject_id, subject_col=id_column,
            db_type=db_type, db_cfg=db_cfg, table=table,
            mode=mode, pii_cols=pii_cols,
        )

    def dsar_export(self, subject_id: str, tables: list[tuple],
                    id_column: str = "id") -> dict:
        """Data Subject Access Request export — returns {table: [rows]}."""
        from sqlalchemy import text

        results: dict = {}
        for entry in tables:
            if len(entry) != 3:
                raise ValueError(f"Each tables entry must be (table, db_type, db_cfg), got {entry}")
            tname, db_type, db_cfg = entry
            _validate_ident(tname, "table")
            _validate_ident(id_column, "id_column")
            try:
                eng = self._build_engine(db_type, db_cfg)
                if eng is None:
                    results[tname] = []
                    continue
                with eng.connect() as conn:
                    rows = conn.execute(
                        text(f"SELECT * FROM {tname} WHERE {id_column} = :sid"),
                        {"sid": subject_id},
                    ).fetchall()
                results[tname] = [dict(r._mapping) for r in rows]
            except Exception as exc:
                logger.warning("DSAR export failed for table %s: %s", tname, exc)
                results[tname] = {"error": str(exc)}

        self.gov._event("DSAR", "DSAR_EXPORT_COMPLETE", {
            "subject_id_hash": hashlib.sha256(str(subject_id).encode()).hexdigest()[:16],
            "tables_queried": list(results.keys()),
            "total_records": sum(len(v) for v in results.values() if isinstance(v, list)),
        })
        return results

    def execute(self, subject_id: str, subject_col: str, db_type: str,
                db_cfg: dict, table: str, mode: str = "delete",
                pii_cols: list[str] | None = None) -> int:
        """Locate and erase all records for a given subject."""
        from sqlalchemy import text

        _validate_ident(table, "table")
        _validate_ident(subject_col, "subject_col")
        if pii_cols:
            for c in pii_cols:
                _validate_ident(c, "pii_col")

        engine = self._build_engine(db_type, db_cfg)
        if engine is None:
            logger.warning("[ERASURE] Unsupported db_type: %s", db_type)
            return 0

        with engine.connect() as conn:
            if mode == "delete":
                result = conn.execute(
                    text(f"DELETE FROM {table} WHERE {subject_col} = :sid"),
                    {"sid": subject_id},
                )
                rows_affected = result.rowcount
                conn.commit()
            elif mode == "nullify" and pii_cols:
                set_clause = ", ".join(f"{c} = NULL" for c in pii_cols)
                result = conn.execute(
                    text(f"UPDATE {table} SET {set_clause} WHERE {subject_col} = :sid"),
                    {"sid": subject_id},
                )
                rows_affected = result.rowcount
                conn.commit()
            else:
                rows_affected = 0

        self.gov.erasure_executed(subject_id, table, rows_affected)
        logger.info(
            "[ERASURE] %s — %d row(s) erased from '%s' (Art. 17)",
            mode.upper(), rows_affected, table,
        )
        return rows_affected

    def _build_engine(self, db_type: str, db_cfg: dict):
        """Build a SQLAlchemy engine for the given database type."""
        from sqlalchemy import create_engine

        t = db_type
        if t == "sqlite":
            return create_engine(f"sqlite:///{db_cfg['db_name']}.db")
        if t in ("postgresql", "postgres"):
            return create_engine(
                f"postgresql+psycopg2://{_qp(db_cfg['user'])}:{_qp(db_cfg['password'])}"
                f"@{db_cfg['host']}:{db_cfg.get('port', 5432)}/{db_cfg['db_name']}"
            )
        if t == "mysql":
            return create_engine(
                f"mysql+pymysql://{_qp(db_cfg['user'])}:{_qp(db_cfg['password'])}"
                f"@{db_cfg['host']}:{db_cfg.get('port', 3306)}/{db_cfg['db_name']}"
            )
        if t == "mssql":
            return create_engine(
                f"mssql+pyodbc://{_qp(db_cfg['user'])}:{_qp(db_cfg['password'])}"
                f"@{db_cfg['host']}:{db_cfg.get('port', 1433)}/{db_cfg['db_name']}"
                f"?driver={db_cfg.get('driver', 'ODBC+Driver+17+for+SQL+Server')}"
            )
        return None
