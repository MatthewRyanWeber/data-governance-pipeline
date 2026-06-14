"""
Durable, tamper-evident append-only audit ledger.

The cryptographic/durability primitive behind the governance audit trail,
extracted from GovernanceLogger so it stands on its own with one reason to
change.  It knows nothing about the pipeline domain (no PII, no tables, no
event vocabulary) — it takes a base event dict, chains it by SHA-256,
writes it durably, and can verify the whole chain afterwards.

Tamper detection has two layers:
  1. Each event carries prev_hash + self_hash, forming a chain where any
     historical edit breaks verification (GDPR Art. 32 integrity).
  2. An anchor sidecar pins the expected final hash and entry count
     OUTSIDE the ledger, so truncating the tail (or deleting the file) —
     which would otherwise leave a still-valid shorter chain — is caught.

Layer 1 — imports from Layer 0 only (helpers, append_only_writer).

Revision history
────────────────
1.0   2026-06-14   Extracted from GovernanceLogger (the _event hash chain,
                   anchor sidecar, and verify_ledger) so the durable-append
                   mechanism is separable and independently testable.
"""

import hashlib
import json
import logging
import threading
from typing import TYPE_CHECKING

from pipeline.helpers import atomic_json_write

if TYPE_CHECKING:
    from pipeline.append_only_writer import AppendOnlyWriter
    from pipeline.run_artifacts import RunArtifacts


class LedgerWriter:
    """
    Append-only, hash-chained, tamper-evident event ledger.

    Quick-start
    ───────────
        writer = LedgerWriter(artifacts, dry_run=False, verify_integrity=False)
        writer.event({"category": "LINEAGE", "action": "LOAD", ...})
        assert writer.verify_ledger()
    """

    def __init__(
        self,
        artifacts: "RunArtifacts",
        dry_run: bool = False,
        verify_integrity: bool = False,
        logger: logging.Logger | None = None,
    ) -> None:
        self.ledger_file = artifacts.ledger_file
        self.ledger_anchor_file = artifacts.ledger_anchor_file
        self.dry_run = dry_run
        self._verify_integrity = verify_integrity
        self.logger = logger or logging.getLogger("DataPipeline")

        # In-memory mirror of the on-disk chain (reports + tests read it).
        self.entries: list[dict] = []
        self._prev_hash: str = "GENESIS"
        self._written_event_count: int = 0
        self._event_lock = threading.RLock()
        self._writer: "AppendOnlyWriter | None" = None

    # Performance: each event() call serialises JSON + computes SHA-256 +
    # writes to disk.  For high-volume pipelines (>100k chunks), consider
    # buffering in self.entries and flushing once per checkpoint interval
    # instead of per-event.  Current design prioritises durability (no
    # events lost on crash) over throughput.
    def event(self, base_entry: dict) -> None:
        """Chain, hash, and durably append one already-built event dict.

        base_entry must already carry the domain fields (category, action,
        detail, pipeline_id, ...); this method adds prev_hash/self_hash,
        writes, and advances the chain.
        """
        with self._event_lock:
            base_entry["prev_hash"] = self._prev_hash
            raw_json = json.dumps(base_entry, sort_keys=True)
            event_hash = hashlib.sha256(raw_json.encode()).hexdigest()
            base_entry["self_hash"] = event_hash
            final_json = json.dumps(base_entry, sort_keys=True)

            if not self.dry_run:
                if self._writer is None:
                    from pipeline.append_only_writer import AppendOnlyWriter
                    self._writer = AppendOnlyWriter(
                        self.ledger_file,
                        verify_integrity=self._verify_integrity,
                    )
                    self._writer.open()
                self._writer.write(final_json + "\n")
                self._written_event_count += 1
                self._write_anchor(event_hash)

            # Advance the chain only after the write lands: if the write
            # raises, the next event reuses this prev_hash and the on-disk
            # chain stays contiguous instead of permanently broken.
            self._prev_hash = event_hash
            self.entries.append(base_entry)

    def _write_anchor(self, last_hash: str) -> None:
        """Persist the chain anchor atomically alongside the ledger.

        The chained hashes alone cannot prove the ledger's *tail* exists:
        truncating the last N lines (or deleting the file) leaves a chain
        that still verifies. The anchor pins the expected final hash and
        entry count outside the ledger file itself.
        """
        anchor = {
            "last_hash": last_hash,
            "entry_count": self._written_event_count,
            "ledger_file": self.ledger_file.name,
        }
        atomic_json_write(self.ledger_anchor_file, json.dumps(anchor, indent=2))

    def _read_anchor(self) -> dict | None:
        """Load the anchor sidecar. Returns None when no anchor exists."""
        if not self.ledger_anchor_file.exists():
            return None
        try:
            anchor = json.loads(
                self.ledger_anchor_file.read_text(encoding="utf-8")
            )
        except (json.JSONDecodeError, OSError) as exc:
            # An unreadable anchor is itself a tamper signal — never treat
            # it as "no anchor", which would let truncation pass unnoticed.
            self.logger.error("[TAMPER CHECK] Anchor file unreadable: %s", exc)
            return {"last_hash": "UNREADABLE", "entry_count": -1}
        if not isinstance(anchor, dict):
            self.logger.error("[TAMPER CHECK] Anchor file malformed (not a dict)")
            return {"last_hash": "UNREADABLE", "entry_count": -1}
        return anchor

    def verify_ledger(self) -> bool:
        """
        Walk the JSONL ledger and verify the chained-hash integrity,
        then check the tail against the persisted anchor.

        Returns True if the entire ledger is intact; False if tampering detected.
        """
        anchor = self._read_anchor()

        if not self.ledger_file.exists():
            if anchor is not None:
                self.logger.error(
                    "[TAMPER DETECTED] Ledger file is missing but anchor "
                    "records %s written events.", anchor.get("entry_count"),
                )
                return False
            return True

        with open(self.ledger_file, encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]

        if not lines:
            if anchor is not None:
                self.logger.error(
                    "[TAMPER DETECTED] Ledger file is empty but anchor "
                    "records %s written events.", anchor.get("entry_count"),
                )
                return False
            return True

        prev_hash = "GENESIS"
        for i, line in enumerate(lines):
            event = json.loads(line)
            stored_prev = event.get("prev_hash", "")
            if stored_prev != prev_hash:
                self.logger.error(
                    "[TAMPER DETECTED] Event #%s (id=%s) "
                    "expected prev_hash=%r but found %r",
                    i + 1, event.get("event_id"), prev_hash, stored_prev,
                )
                return False

            entry_for_hash = {k: v for k, v in event.items() if k != "self_hash"}
            computed_hash = hashlib.sha256(
                json.dumps(entry_for_hash, sort_keys=True).encode()
            ).hexdigest()
            stored_self = event.get("self_hash")
            if stored_self and stored_self != computed_hash:
                self.logger.error(
                    "[TAMPER DETECTED] Event #%s (id=%s) "
                    "self_hash mismatch — event content has been altered",
                    i + 1, event.get("event_id"),
                )
                return False
            prev_hash = computed_hash

        if anchor is not None:
            if anchor.get("entry_count") != len(lines):
                self.logger.error(
                    "[TAMPER DETECTED] Ledger has %s events but anchor "
                    "records %s — tail truncation suspected.",
                    len(lines), anchor.get("entry_count"),
                )
                return False
            if anchor.get("last_hash") != prev_hash:
                self.logger.error(
                    "[TAMPER DETECTED] Final ledger hash %r does not match "
                    "anchored hash %r.", prev_hash, anchor.get("last_hash"),
                )
                return False

        self.logger.info(
            "[TAMPER CHECK] Ledger integrity verified — %s events OK.", len(lines)
        )
        return True
