"""
Custom exceptions for the pipeline package.

Layer 0 — no internal package imports.

Revision history
────────────────
1.0   2026-06-07   Initial release: ContractViolationError.
1.1   2026-06-08   Added ConfigValidationError, LoaderError, ExtractionError,
                   ValidationError for structured error handling.
1.2   2026-06-09   Added CircuitOpenError for circuit breaker pattern.
"""


class ConfigValidationError(ValueError):
    """
    Raised when a loader or component receives an invalid configuration dict.

    Attributes
    ----------
    db_type     : str        The loader's db_type (e.g. "postgresql", "snowflake").
    missing_keys: list[str]  Config keys that were required but absent.
    """

    def __init__(
        self,
        db_type: str = "",
        missing_keys: list[str] | None = None,
        message: str = "",
    ) -> None:
        self.db_type = db_type
        self.missing_keys = missing_keys or []
        if not message:
            message = (
                f"Invalid config for '{db_type}': "
                f"missing required key(s): {', '.join(self.missing_keys)}"
            )
        super().__init__(message)


class LoaderError(Exception):
    """
    Raised when a loader fails to write data to the destination.

    Attributes
    ----------
    db_type : str  The target database type.
    table   : str  The target table or collection name.
    """

    def __init__(
        self,
        db_type: str = "",
        table: str = "",
        message: str = "",
    ) -> None:
        self.db_type = db_type
        self.table = table
        if not message:
            message = f"Load failed for '{db_type}' table '{table}'"
        super().__init__(message)


class ExtractionError(Exception):
    """
    Raised when source file extraction or parsing fails.

    Attributes
    ----------
    source : str  The source file path.
    format : str  The detected file format extension.
    """

    def __init__(
        self,
        source: str = "",
        format: str = "",
        message: str = "",
    ) -> None:
        self.source = source
        self.format = format
        if not message:
            message = f"Extraction failed for '{source}' (format: {format})"
        super().__init__(message)


class ValidationError(Exception):
    """
    Raised when business rule or schema validation fails.

    Attributes
    ----------
    rule_name : str        The rule or validation that failed.
    details   : list[dict] Structured failure details.
    """

    def __init__(
        self,
        rule_name: str = "",
        details: list[dict] | None = None,
        message: str = "",
    ) -> None:
        self.rule_name = rule_name
        self.details = details or []
        if not message:
            message = (
                f"Validation failed: '{rule_name}' "
                f"with {len(self.details)} issue(s)"
            )
        super().__init__(message)


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


class CircuitOpenError(Exception):
    """
    Raised when a circuit breaker is open and rejecting requests.

    Attributes
    ----------
    breaker_name : str  The name of the open circuit breaker.
    """

    def __init__(self, breaker_name: str = "") -> None:
        self.breaker_name = breaker_name
        super().__init__(
            f"Circuit breaker '{breaker_name}' is OPEN — requests are being rejected. "
            "The destination may be unavailable."
        )
