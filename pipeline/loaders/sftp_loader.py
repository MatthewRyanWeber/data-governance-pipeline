"""
SFTP loader -- writes governed DataFrames to remote servers via SFTP
using Paramiko, serialised as CSV, JSON, JSONL, or Parquet.

Layer 4 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-07   Extracted from pipeline_v3.py (class SFTPLoader).
1.1   2026-06-07   Added Layer 4 docstring convention.
"""

import logging
from typing import TYPE_CHECKING

from pipeline.constants import HAS_SFTP

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class SFTPLoader:
    """Upload DataFrames to remote SFTP servers."""

    _FORMATS = ("csv", "json", "jsonl", "parquet")

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov
        if not HAS_SFTP:
            raise RuntimeError(
                "SFTPLoader requires the paramiko package.\n"
                "Install with:  pip install paramiko"
            )

    def load(self, df, cfg, table="", if_exists="replace",
             natural_keys=None) -> int:
        """Upload df to an SFTP server."""
        import paramiko

        host = cfg.get("host")
        username = cfg.get("username")
        remote_path = cfg.get("remote_path") or (
            f"{table}.{cfg.get('format', 'csv')}" if table else ""
        )
        port = int(cfg.get("port", 22))
        timeout = int(cfg.get("timeout", 30))
        fmt = cfg.get("format", "csv").lower()

        if not host:
            raise ValueError("SFTPLoader: cfg must contain 'host'.")
        if not username:
            raise ValueError("SFTPLoader: cfg must contain 'username'.")
        if not remote_path:
            raise ValueError(
                "SFTPLoader: supply remote path via cfg['remote_path'] or "
                "the table parameter."
            )
        if fmt not in self._FORMATS:
            raise ValueError(
                f"SFTPLoader: format must be one of {self._FORMATS}, "
                f"got '{fmt}'."
            )

        if df.empty:
            return 0

        body = self._serialise(df, fmt, cfg)

        ssh = paramiko.SSHClient()
        if cfg.get("auto_add_host_key", False):
            logger.warning(
                "SFTPLoader: auto_add_host_key is enabled — accepting any "
                "host key. This is vulnerable to MITM attacks."
            )
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        else:
            ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
            known_hosts = cfg.get("known_hosts_file")
            if known_hosts:
                import os
                ssh.load_host_keys(os.path.expanduser(known_hosts))
            else:
                ssh.load_system_host_keys()

        connect_kwargs: dict = {
            "hostname": host,
            "port": port,
            "username": username,
            "timeout": timeout,
        }
        if cfg.get("private_key"):
            import os
            key_path = os.path.expanduser(cfg["private_key"])
            passphrase = cfg.get("private_key_passphrase")
            connect_kwargs["key_filename"] = key_path
            if passphrase:
                connect_kwargs["passphrase"] = passphrase
        else:
            connect_kwargs["password"] = cfg.get("password", "")

        try:
            ssh.connect(**connect_kwargs)
            sftp = ssh.open_sftp()
            with sftp.file(remote_path, "wb") as remote_file:
                remote_file.write(body)
            sftp.close()
        finally:
            ssh.close()

        self.gov._event(
            "LOAD", "SFTP_WRITE_COMPLETE",
            {
                "host": host,
                "remote_path": remote_path,
                "rows": len(df),
                "format": fmt,
            },
        )
        return len(df)

    @staticmethod
    def _serialise(df, fmt, cfg) -> bytes:
        import io
        if fmt == "parquet":
            import pyarrow as pa
            import pyarrow.parquet as pq
            buf = io.BytesIO()
            pq.write_table(pa.Table.from_pandas(df, preserve_index=False),
                           buf, compression=cfg.get("compression", "snappy"))
            return buf.getvalue()
        if fmt == "csv":
            return df.to_csv(index=False).encode("utf-8")
        if fmt == "json":
            return df.to_json(orient="records", indent=2).encode("utf-8")
        if fmt == "jsonl":
            return df.to_json(orient="records", lines=True).encode("utf-8")
        raise ValueError(f"SFTPLoader: unknown format '{fmt}'")
