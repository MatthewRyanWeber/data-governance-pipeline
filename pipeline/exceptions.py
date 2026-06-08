"""
Custom exceptions for the pipeline package.

Layer 0 — no internal package imports.
"""


class ContractViolationError(Exception):
    """Raised when a data contract validation fails at CRITICAL severity."""

    def __init__(self, violations: list[dict] | None = None, message: str = ""):
        self.violations = violations or []
        super().__init__(message or f"{len(self.violations)} contract violation(s)")
