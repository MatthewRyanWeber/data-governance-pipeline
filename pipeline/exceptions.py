"""
Custom exceptions for the pipeline package.

Layer 0 — no internal package imports.
"""


class ContractViolationError(Exception):
    """
    Raised by DataContractEnforcer.enforce() when one or more CRITICAL
    or ERROR contract clauses are violated.

    Attributes
    ----------
    contract_name : str        Name from the contract YAML.
    violations    : list[dict] CRITICAL + ERROR violations.
    warnings      : list[dict] WARNING violations (non-fatal).
    """

    def __init__(
        self,
        contract_name: str = "",
        violations: list[dict] | None = None,
        warnings: list[dict] | None = None,
    ) -> None:
        self.contract_name = contract_name
        self.violations = violations or []
        self.warnings = warnings or []
        summary = (
            f"Contract '{contract_name}' violated: "
            f"{len(self.violations)} failure(s), {len(self.warnings)} warning(s)\n"
        )
        details = "\n".join(
            f"  [{v['severity']}] {v['clause']}.{v['rule']}"
            + (f" [{v['column']}]" if v.get("column") else "")
            + f" — expected: {v['expected']}  actual: {v['actual']}"
            for v in self.violations
        )
        super().__init__(summary + details)
