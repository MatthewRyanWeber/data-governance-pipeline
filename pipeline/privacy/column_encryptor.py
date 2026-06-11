"""
AES-256 symmetric encryption for DataFrame columns using Fernet.

Two-way encryption (unlike SHA-256 masking) — values can be recovered
by authorised parties with the key. GDPR Art. 32 / CCPA §1798.150.

Layer 3 — imports from Layer 0 (constants), Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-08   Initial release.
1.1   2026-06-11   Exposed in-use key via active_key property (the old warning
                   pointed at generate_key(), which mints a NEW key — following
                   it lost the data); cast columns to object dtype before
                   assigning ciphertext (pandas 3.x raises on numeric columns).
"""

import logging
from typing import TYPE_CHECKING

from pipeline.constants import HAS_CRYPTO

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class ColumnEncryptor:
    """
    Encrypts/decrypts DataFrame columns with Fernet (AES-256-CBC).

    Quick-start
    -----------
        from pipeline.privacy import ColumnEncryptor
        key = ColumnEncryptor.generate_key()
        enc = ColumnEncryptor(gov, key)
        df = enc.encrypt(df, ["ssn", "credit_card"])
        df = enc.decrypt(df, ["ssn", "credit_card"])
    """

    def __init__(self, gov: "GovernanceLogger", key: str | None = None) -> None:
        self.gov = gov
        self._active_key: str | None = None
        if not HAS_CRYPTO:
            logger.warning("[ENCRYPT] cryptography library not installed — encryption disabled.")
            self._fernet = None
            return

        from cryptography.fernet import Fernet

        if key:
            key_bytes = key.encode() if isinstance(key, str) else key
            self._fernet = Fernet(key_bytes)
            self._active_key = key_bytes.decode()
        else:
            new_key = Fernet.generate_key()
            self._fernet = Fernet(new_key)
            self._active_key = new_key.decode()
            logger.warning(
                "[ENCRYPT] No key provided — generated new key. "
                "Read it from the active_key property and store it securely "
                "before this process exits, or the data is unrecoverable.",
            )

    @property
    def active_key(self) -> str | None:
        """The key this instance encrypts and decrypts with.

        This is the only handle on an auto-generated key — generate_key()
        returns a fresh random key every call and can never recover it.
        Returns None when the cryptography library is unavailable.
        """
        return self._active_key

    @staticmethod
    def generate_key() -> str:
        """Mint a NEW random Fernet key — unrelated to any instance's key."""
        if HAS_CRYPTO:
            from cryptography.fernet import Fernet
            return Fernet.generate_key().decode()
        raise RuntimeError("cryptography library not installed")

    def encrypt(self, df, columns: list[str]):
        """Encrypt specified columns. Null values are left as null."""
        if not self._fernet:
            return df
        fernet = self._fernet
        for col in columns:
            if col not in df.columns:
                continue
            mask = df[col].notna()
            if mask.any():
                vals = df.loc[mask, col].astype(str).tolist()
                encrypted = [
                    "ENCRYPTED:" + fernet.encrypt(v.encode()).decode()
                    for v in vals
                ]
                # Ciphertext is a string; assigning it into an int/float
                # column raises TypeError under pandas 3.x.
                if df[col].dtype != object:
                    df[col] = df[col].astype(object)
                df.loc[mask, col] = encrypted
            self.gov.encryption_applied(col, "AES-256-CBC/Fernet")
        return df

    def decrypt(self, df, columns: list[str]):
        """Decrypt previously-encrypted columns."""
        if not self._fernet:
            return df
        fernet = self._fernet
        prefix = "ENCRYPTED:"
        prefix_len = len(prefix)
        for col in columns:
            if col not in df.columns:
                continue
            mask = df[col].notna() & df[col].astype(str).str.startswith(prefix)
            if mask.any():
                vals = df.loc[mask, col].astype(str).tolist()
                decrypted = []
                for v in vals:
                    try:
                        decrypted.append(
                            fernet.decrypt(v[prefix_len:].encode()).decode()
                        )
                    except Exception as exc:
                        logger.error("Decryption failed for column '%s': %s — value left encrypted", col, exc)
                        decrypted.append(v)
                df.loc[mask, col] = decrypted
        return df
