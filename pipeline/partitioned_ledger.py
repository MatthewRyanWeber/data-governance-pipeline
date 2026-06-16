"""
Partitionable tamper-evident ledger — a Merkle root over independent per-segment
hash chains.

This is the ledger half of "Path A" (scaling governance to a distributed,
100TB/day run). The single-file LedgerWriter is serial by construction — one
writer, one append-only chain — so it is the contention point and bottleneck
when N workers each govern a partition. Here every partition gets its OWN
segment: an independent LedgerWriter chain in its own file, written with zero
coordination between workers. After the run, the segment heads are composed
into a single Merkle root.

Verification has the same two-layer guarantee as the single-file ledger, now
per shard plus a root:
  1. each segment's internal SHA-256 chain (any historical edit breaks it);
  2. a Merkle root over the segment heads, persisted as the root anchor — so a
     segment that is altered, dropped, added, or renamed changes the root and
     is detected. The Merkle structure also yields O(log n) inclusion proofs,
     so one partition can be audited without reading all the others.

As with the single-file anchor, the root is the external trust value: publish
the merkle_root to a WORM/notary store to make the whole ledger tamper-evident
against an attacker who can rewrite the files.

Layer 1 — imports Layer 0 (helpers) and Layer 1 (ledger_writer).

Revision history
────────────────
1.0   2026-06-15   Initial release: per-partition segments, Merkle root anchor,
                   verification, and inclusion proofs.
1.1   2026-06-16   Hardening: segment_id rejects "." / ".." (the charset allowed
                   them, but they escape the ledger root when used as a path
                   component); a corrupt/unreadable segment anchor is treated as
                   tamper (verify→False) instead of crashing; verify() reads
                   segments read-only (dry_run) so it never mutates anchors.
"""

import hashlib
import json
import logging
import re
from pathlib import Path

from pipeline.helpers import atomic_json_write
from pipeline.ledger_writer import LedgerWriter

logger = logging.getLogger("DataPipeline")

# Segment ids become filename components, so constrain them tightly.
_SEGMENT_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_ROOT_ANCHOR_NAME = "ledger.root.json"
_SEG_PREFIX = "segment-"
_SEG_SUFFIX = ".jsonl"
_ANCHOR_SUFFIX = ".jsonl.anchor"

# Sentinel head for a segment whose anchor cannot be read — guarantees a leaf
# that no intact segment can produce (a real last_hash is 64 hex chars), so the
# Merkle root mismatches and verify returns False (tamper) rather than the run
# crashing on a corrupt anchor. Spelling matches LedgerWriter._read_anchor.
_UNREADABLE_HEAD = {"entry_count": -1, "last_hash": "UNREADABLE"}


def validate_segment_id(segment_id: str) -> str:
    """Validate a segment id as a safe filename AND path component.

    The single check both the ledger (filename) and the governance entrypoint
    (which derives a per-segment ``log_dir = root_dir / segment_id``) call.
    "." and ".." pass the charset regex but escape the ledger root when used
    as a path component, so they are rejected explicitly.
    """
    if segment_id in (".", "..") or not _SEGMENT_ID_RE.match(segment_id):
        raise ValueError(
            f"Invalid segment_id {segment_id!r}: must match "
            f"{_SEGMENT_ID_RE.pattern} and not be '.' or '..'"
        )
    return segment_id


def _sha(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _leaf_hash(segment_id: str, count: int, head: str) -> str:
    # NUL-separated so distinct (id, count, head) tuples can't collide.
    return _sha(f"{segment_id}\0{count}\0{head}")


def _merkle_levels(leaves: list[str]) -> list[list[str]]:
    """Bottom-up Merkle levels; levels[0] is the leaves, levels[-1] is [root]."""
    if not leaves:
        return [[_sha("EMPTY-LEDGER")]]
    levels = [list(leaves)]
    while len(levels[-1]) > 1:
        cur = levels[-1]
        if len(cur) % 2:
            cur = cur + [cur[-1]]  # duplicate the last node for an odd count
        levels.append([_sha(cur[i] + cur[i + 1]) for i in range(0, len(cur), 2)])
    return levels


def _merkle_root(leaves: list[str]) -> str:
    return _merkle_levels(leaves)[-1][0]


def _inclusion_proof(leaves: list[str], index: int) -> list[dict]:
    """Sibling hashes from leaf->root; each step records which side the sibling is."""
    levels = _merkle_levels(leaves)
    proof: list[dict] = []
    for level in levels[:-1]:
        cur = level if len(level) % 2 == 0 else level + [level[-1]]
        sibling_on_right = index % 2 == 0
        proof.append({"right": sibling_on_right, "hash": cur[index ^ 1]})
        index //= 2
    return proof


def verify_inclusion(leaf: str, proof: list[dict], root: str) -> bool:
    """True if `leaf` combines up `proof` to `root`."""
    h = leaf
    for step in proof:
        h = _sha(h + step["hash"]) if step["right"] else _sha(step["hash"] + h)
    return h == root


class _SegmentPaths:
    """Duck-typed RunArtifacts: just the two path attributes LedgerWriter reads."""

    def __init__(self, ledger_file: Path) -> None:
        self.ledger_file = ledger_file
        self.ledger_anchor_file = ledger_file.with_name(ledger_file.name + ".anchor")


class PartitionedLedger:
    """
    A tamper-evident ledger sharded into independent per-partition chains.

    Quick-start
    ───────────
        led = PartitionedLedger("run_ledger/")
        # each worker, independently and concurrently:
        seg = led.segment("part-0007")
        seg.event({"category": "LOAD", "action": "...", ...})
        # once, after all workers finish:
        root = led.seal()["merkle_root"]
        assert led.verify()
    """

    def __init__(
        self,
        root_dir,
        dry_run: bool = False,
        verify_integrity: bool = False,
        logger_: logging.Logger | None = None,
    ) -> None:
        self.root_dir = Path(root_dir)
        self.dry_run = dry_run
        self._verify_integrity = verify_integrity
        self.logger = logger_ or logger
        if not dry_run:
            self.root_dir.mkdir(parents=True, exist_ok=True)

    def _segment_file(self, segment_id: str) -> Path:
        validate_segment_id(segment_id)
        return self.root_dir / f"{_SEG_PREFIX}{segment_id}{_SEG_SUFFIX}"

    def segment(self, segment_id: str) -> LedgerWriter:
        """An independent ledger chain for one partition.

        Each segment is a distinct file with its own chain and anchor, so many
        workers can call this and write concurrently with no shared state and
        no lock contention — the property the single-file ledger lacks.
        """
        return self._segment(segment_id, dry_run=self.dry_run)

    def _segment(self, segment_id: str, *, dry_run: bool) -> LedgerWriter:
        return LedgerWriter(
            # Structural shim: LedgerWriter only reads .ledger_file and
            # .ledger_anchor_file off its artifacts arg, which _SegmentPaths
            # provides — it just isn't the nominal RunArtifacts type.
            _SegmentPaths(self._segment_file(segment_id)),  # type: ignore[arg-type]
            dry_run=dry_run,
            verify_integrity=self._verify_integrity,
            logger=self.logger,
        )

    def _segment_heads(self) -> list[dict]:
        """(segment_id, entry_count, last_hash) per segment, sorted by id."""
        heads = []
        for anchor in self.root_dir.glob(f"{_SEG_PREFIX}*{_ANCHOR_SUFFIX}"):
            seg_id = anchor.name[len(_SEG_PREFIX):-len(_ANCHOR_SUFFIX)]
            try:
                data = json.loads(anchor.read_text(encoding="utf-8"))
                if not isinstance(data, dict):
                    raise ValueError("anchor is not a JSON object")
            except (OSError, ValueError) as exc:
                # A corrupt/unreadable anchor is a tamper signal, not a reason
                # to crash the whole verification. Emit a sentinel head so the
                # recomputed Merkle root cannot match the sealed root.
                self.logger.error(
                    "[TAMPER DETECTED] Segment %s anchor unreadable: %s", seg_id, exc
                )
                data = _UNREADABLE_HEAD
            heads.append({
                "segment_id": seg_id,
                "entry_count": int(data.get("entry_count", 0)),
                "last_hash": data.get("last_hash", ""),
            })
        heads.sort(key=lambda h: h["segment_id"])
        return heads

    @staticmethod
    def _leaves(heads: list[dict]) -> list[str]:
        return [_leaf_hash(h["segment_id"], h["entry_count"], h["last_hash"]) for h in heads]

    def seal(self) -> dict:
        """Compose the current segment heads into a Merkle root and persist the
        root anchor. Call once after all workers have finished."""
        heads = self._segment_heads()
        record = {
            "merkle_root": _merkle_root(self._leaves(heads)),
            "segment_count": len(heads),
            "total_events": sum(h["entry_count"] for h in heads),
            "segments": heads,
        }
        if not self.dry_run:
            atomic_json_write(
                self.root_dir / _ROOT_ANCHOR_NAME, json.dumps(record, indent=2)
            )
        return record

    def verify(self) -> bool:
        """Verify every segment's chain AND the Merkle root over the heads."""
        root_path = self.root_dir / _ROOT_ANCHOR_NAME
        if not root_path.exists():
            self.logger.error(
                "[TAMPER DETECTED] Partitioned ledger is not sealed (no root anchor)."
            )
            return False
        stored = json.loads(root_path.read_text(encoding="utf-8"))

        # 1) each sealed segment's internal hash chain (reuses LedgerWriter).
        # Read-only (dry_run): verify must never mutate the anchors it audits —
        # LedgerWriter's crash-during-append catch-up rewrites the anchor unless
        # dry_run is set, which would let a verify pass silently "fix" a segment.
        for head in stored.get("segments", []):
            if not self._segment(head["segment_id"], dry_run=True).verify_ledger():
                self.logger.error(
                    "[TAMPER DETECTED] Segment %s failed chain verification.",
                    head["segment_id"],
                )
                return False

        # 2) recompute the root over the CURRENT heads on disk. A segment that
        # was added, dropped, renamed, or whose head changed shifts the root.
        if _merkle_root(self._leaves(self._segment_heads())) != stored.get("merkle_root"):
            self.logger.error(
                "[TAMPER DETECTED] Merkle root mismatch — a segment was added, "
                "removed, renamed, or altered since sealing."
            )
            return False

        self.logger.info(
            "[TAMPER CHECK] Partitioned ledger verified — %s segments, %s events.",
            stored.get("segment_count"), stored.get("total_events"),
        )
        return True

    def inclusion_proof(self, segment_id: str) -> dict:
        """O(log n) proof that `segment_id` is part of the sealed root.

        Lets one partition's audit trail be verified against the root without
        reading every other segment — the Merkle payoff at scale.
        """
        heads = self._segment_heads()
        try:
            index = next(i for i, h in enumerate(heads) if h["segment_id"] == segment_id)
        except StopIteration:
            raise ValueError(f"segment_id {segment_id!r} not found")
        leaves = self._leaves(heads)
        return {
            "segment_id": segment_id,
            "leaf": leaves[index],
            "proof": _inclusion_proof(leaves, index),
            "merkle_root": _merkle_root(leaves),
        }
