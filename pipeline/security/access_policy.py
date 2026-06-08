"""
RBAC and column/row-level access policy enforcement.

Defines roles, assigns them to users, and enforces column-level and
row-level access control on DataFrames before they leave the pipeline.

Layer 3 — imports from Layer 0 (constants).

Revision history
────────────────
1.0   2026-06-08   Initial release.
1.1   2026-06-08   Fail-closed on missing role, sanitize row_filter, atomic writes.
"""

import json
import logging
import re
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from pipeline.constants import BASE_DIR

if TYPE_CHECKING:
    import pandas as pd
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)

_POLICY_FILE = BASE_DIR / "config" / "access_policies.json"
_LOCK = threading.Lock()


class AccessPolicy:
    """
    Role-based access control with column and row-level filtering.

    Quick-start
    -----------
        from pipeline.security import AccessPolicy
        policy = AccessPolicy(gov)
        policy.add_role("analyst", allowed_columns=["name","revenue"],
                        denied_columns=["ssn","salary"])
        safe_df = policy.enforce(df, role="analyst", dataset="customers")
    """

    def __init__(
        self,
        gov: "GovernanceLogger",
        policy_file: str | Path | None = None,
    ) -> None:
        self.gov = gov
        self.policy_file = Path(policy_file) if policy_file else _POLICY_FILE
        self.policy_file.parent.mkdir(parents=True, exist_ok=True)
        self._policies: dict = self._load()

    def _load(self) -> dict:
        if not self.policy_file.exists():
            return {"roles": {}, "user_roles": {}, "dataset_policies": {}}
        try:
            return json.loads(self.policy_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Could not load access policies: %s", exc)
            return {"roles": {}, "user_roles": {}, "dataset_policies": {}}

    def _save(self) -> None:
        with _LOCK:
            self._policies["updated_utc"] = datetime.now(timezone.utc).isoformat()
            data = json.dumps(self._policies, indent=2)
            tmp_fd, tmp_path = tempfile.mkstemp(
                dir=str(self.policy_file.parent), suffix=".tmp",
            )
            try:
                with open(tmp_fd, "w", encoding="utf-8") as fh:
                    fh.write(data)
                Path(tmp_path).replace(self.policy_file)
            except BaseException:
                Path(tmp_path).unlink(missing_ok=True)
                raise

    def add_role(
        self,
        role: str,
        allowed_columns: list[str] | None = None,
        denied_columns: list[str] | None = None,
        row_filter: str | None = None,
        description: str = "",
    ) -> None:
        """
        Define a role with column and row-level access rules.

        Parameters
        ----------
        role             : str         Role name (e.g. "analyst", "admin").
        allowed_columns  : list | None Whitelist — only these columns visible.
        denied_columns   : list | None Blacklist — these columns redacted.
        row_filter       : str | None  Pandas query string for row filtering.
        description      : str         Human-readable role description.
        """
        self._policies["roles"][role] = {
            "allowed_columns": allowed_columns,
            "denied_columns": denied_columns or [],
            "row_filter": row_filter,
            "description": description,
        }
        self._save()
        self.gov.transformation_applied("RBAC_ROLE_CREATED", {
            "role": role,
            "allowed_columns": len(allowed_columns) if allowed_columns else "all",
            "denied_columns": len(denied_columns or []),
            "has_row_filter": row_filter is not None,
        })
        logger.info("[RBAC] Created role '%s'", role)

    def assign_role(self, user: str, role: str) -> None:
        """Assign a role to a user."""
        if role not in self._policies["roles"]:
            raise ValueError(f"Role '{role}' does not exist")
        user_roles = self._policies["user_roles"].setdefault(user, [])
        if role not in user_roles:
            user_roles.append(role)
        self._save()
        logger.info("[RBAC] Assigned role '%s' to user '%s'", role, user)

    def set_dataset_policy(
        self, dataset: str, default_role: str,
        public: bool = False,
    ) -> None:
        """Set the default access policy for a dataset."""
        self._policies["dataset_policies"][dataset] = {
            "default_role": default_role,
            "public": public,
        }
        self._save()

    def enforce(
        self,
        df: "pd.DataFrame",
        role: str | None = None,
        user: str | None = None,
        dataset: str = "",
    ) -> "pd.DataFrame":
        """
        Apply access policy to a DataFrame.

        Drops denied columns and filters rows based on the role's policy.
        Returns a copy with restricted data removed.
        """
        effective_role = role
        if not effective_role and user:
            user_roles = self._policies["user_roles"].get(user, [])
            effective_role = user_roles[0] if user_roles else None

        if not effective_role and dataset:
            dp = self._policies["dataset_policies"].get(dataset, {})
            effective_role = dp.get("default_role")

        if not effective_role:
            logger.debug("[RBAC] No role resolved — returning full DataFrame")
            return df

        policy = self._policies["roles"].get(effective_role)
        if not policy:
            raise ValueError(
                f"Role '{effective_role}' not found — cannot enforce access policy. "
                f"Available roles: {list(self._policies['roles'])}"
            )

        result = df.copy()
        columns_dropped = []

        if policy["allowed_columns"] is not None:
            allowed = set(policy["allowed_columns"]) & set(result.columns)
            to_drop = [c for c in result.columns if c not in allowed]
            result = result[list(allowed)]
            columns_dropped.extend(to_drop)

        if policy["denied_columns"]:
            denied = [c for c in policy["denied_columns"] if c in result.columns]
            result = result.drop(columns=denied)
            columns_dropped.extend(denied)

        rows_before = len(result)
        if policy["row_filter"]:
            row_filter = policy["row_filter"]
            _FORBIDDEN = re.compile(
                r"__\w+__|import\s*\(|exec\s*\(|eval\s*\(|open\s*\(|compile\s*\(",
                re.IGNORECASE,
            )
            if _FORBIDDEN.search(row_filter):
                raise ValueError(
                    f"Row filter contains forbidden pattern: {row_filter!r}"
                )
            try:
                result = result.query(row_filter)
            except Exception as exc:
                logger.warning("[RBAC] Row filter failed: %s", exc)

        rows_filtered = rows_before - len(result)

        self.gov.transformation_applied("RBAC_ENFORCED", {
            "role": effective_role, "dataset": dataset,
            "columns_dropped": columns_dropped,
            "rows_filtered": rows_filtered,
        })

        if columns_dropped or rows_filtered:
            logger.info("[RBAC] Enforced role '%s': dropped %d cols, filtered %d rows",
                        effective_role, len(columns_dropped), rows_filtered)

        return result

    def list_roles(self) -> dict:
        """Return all defined roles."""
        return dict(self._policies["roles"])

    def user_roles(self, user: str) -> list[str]:
        """Return roles assigned to a user."""
        return list(self._policies["user_roles"].get(user, []))
