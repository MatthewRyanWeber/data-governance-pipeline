"""
Canary / soak harness.

Runs a fixed synthetic dataset through the real governance core — PII detect →
mask → governed load to sqlite → ledger verify — and appends a verifiable
track-record entry (timing, row count, ledger-verified, pass/fail) to a JSONL.
Run on a schedule, the accumulating track record is the "production miles"
evidence a governance system needs: not one demo run, but a dated history of
ledger-verified runs over time.

Everything is synthetic and local — no network, no real PII — so it is safe to
run anywhere and cheap enough to loop.

Layer 4 — composes governance_logger, transform, helpers, and the SQL loader.

Revision history
────────────────
1.0   2026-06-18   Initial release: governed canary run + track record + soak loop.
"""

import json
import logging
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from pipeline.constants import VERSION
from pipeline.helpers import detect_pii

logger = logging.getLogger(__name__)

_DEFAULT_TRACK_RECORD = Path("examples") / "canary" / "track_record.jsonl"


class CanaryRunner:
    """
    Drives a fixed governed run and records a pass/fail track record.

    Quick-start
    -----------
        from pipeline.monitoring.canary import CanaryRunner
        runner = CanaryRunner()
        record = runner.run_once()          # one governed run, appended to history
        summary = runner.summarize_history() # pass rate over all runs
    """

    def __init__(
        self,
        track_record_path: str | Path | None = None,
        rows: int = 200,
        dry_run: bool = False,
    ) -> None:
        self.track_record_path = Path(track_record_path or _DEFAULT_TRACK_RECORD)
        self.rows = rows
        self.dry_run = dry_run
        self._lock = threading.Lock()

    def _sample_frame(self):
        """Deterministic synthetic frame with PII-named columns (no real data)."""
        import pandas as pd

        return pd.DataFrame({
            "id": list(range(self.rows)),
            "full_name": [f"User {i}" for i in range(self.rows)],
            "email": [f"user{i}@example.com" for i in range(self.rows)],
            "phone": [f"555-01{i % 100:02d}" for i in range(self.rows)],
            "amount": [round((i % 1000) + 0.5, 2) for i in range(self.rows)],
        })

    def verify_ledger_chain(self, ledger_path) -> bool:
        """Independent hash-chain check: each entry's prev_hash == prior self_hash.

        A second, dependency-free check alongside gov.verify_ledger() so a canary
        failure can't hide behind the same code path that wrote the ledger.
        """
        path = Path(ledger_path)
        if not path.exists():
            return False
        rows = [json.loads(line) for line in
                path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if not rows:
            return False
        for earlier, later in zip(rows, rows[1:]):
            if later.get("prev_hash") != earlier.get("self_hash"):
                return False
        return True

    def run_once(self, workdir: str | Path | None = None) -> dict:
        """Run one governed canary and append its result to the track record."""
        from pipeline.governance_logger import GovernanceLogger
        from pipeline.transform import Transformer
        from pipeline.loaders.sql_loader import SQLLoader

        work = Path(workdir) if workdir else Path(tempfile.mkdtemp(prefix="canary_"))
        started = datetime.now(timezone.utc)
        start_perf = time.perf_counter()
        status = "pass"
        error = None
        rows = 0
        ledger_verified = False

        try:
            gov = GovernanceLogger(source_name="canary", log_dir=str(work / "gov"))
            df = self._sample_frame()
            rows = len(df)

            findings = detect_pii(list(df.columns))
            transformed = Transformer(gov).transform(df, findings, "mask", drop_cols=[])

            loader = SQLLoader(gov, db_type="sqlite")
            loaded = loader.load(transformed, {"db_name": str(work / "canary.db")}, "canary")
            loader.close()

            ledger_verified = gov.verify_ledger()
            chain_ok = self.verify_ledger_chain(gov.ledger_file)
            if not (ledger_verified and chain_ok and loaded == rows):
                status = "fail"
        except Exception as exc:
            status = "fail"
            error = repr(exc)
            logger.exception("[CANARY] run failed")

        record = {
            "utc": started.isoformat(),
            "status": status,
            "rows": rows,
            "duration_sec": round(time.perf_counter() - start_perf, 4),
            "ledger_verified": ledger_verified,
            "version": VERSION,
        }
        if error:
            record["error"] = error

        self.append_record(record)
        logger.info("[CANARY] %s — %d rows, %.3fs, ledger_verified=%s",
                    status.upper(), rows, record["duration_sec"], ledger_verified)
        return record

    def append_record(self, record: dict) -> None:
        """Append one record to the track-record JSONL (atomic per-line, locked)."""
        if self.dry_run:
            logger.info("[CANARY] dry_run — would append %s record", record["status"])
            return
        with self._lock:
            self.track_record_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.track_record_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")

    def summarize_history(self) -> dict:
        """Aggregate the track record: run count, pass rate, last status."""
        if not self.track_record_path.exists():
            return {"runs": 0, "passed": 0, "failed": 0, "pass_rate": None,
                    "last_status": None}
        records = [json.loads(line) for line in
                   self.track_record_path.read_text(encoding="utf-8").splitlines()
                   if line.strip()]
        passed = sum(1 for r in records if r.get("status") == "pass")
        total = len(records)
        return {
            "runs": total,
            "passed": passed,
            "failed": total - passed,
            "pass_rate": round(passed / total, 4) if total else None,
            "last_status": records[-1].get("status") if records else None,
        }

    def soak(self, runs: int, interval_sec: float = 0.0) -> dict:
        """Run the canary `runs` times (a soak), returning the history summary.

        A non-zero `interval_sec` paces the loop; callers wanting a long-lived
        scheduled canary should instead invoke run_once() from cron/Task
        Scheduler so each run is an isolated process.
        """
        for index in range(runs):
            self.run_once()
            if interval_sec and index < runs - 1:
                time.sleep(interval_sec)
        return self.summarize_history()
