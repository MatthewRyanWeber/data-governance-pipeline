"""
Interactive GDPR/CCPA compliance wizard.

Guides the operator through lawful basis selection, PII strategy,
retention policy, and data minimisation choices.

Layer 6 — imports from Layer 0 (helpers), Layer 1 (governance_logger).
"""

import logging
from typing import TYPE_CHECKING

from pipeline.helpers import interactive_prompt, confirm_yes_no

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


def run_compliance_wizard(gov: "GovernanceLogger", pii_findings: list[dict]) -> dict:
    """
    Interactive compliance wizard — collects GDPR/CCPA processing decisions.

    Returns a dict with: lawful_basis, purpose, pii_strategy, retention_days, drop_cols.
    """
    print("\n" + "=" * 64)
    print("  GDPR / CCPA COMPLIANCE WIZARD")
    print("=" * 64)

    bases = {
        "1": "Consent", "2": "Contract", "3": "Legal Obligation",
        "4": "Vital Interests", "5": "Public Task", "6": "Legitimate Interests",
    }
    for k, v in bases.items():
        print(f"  {k}. {v}")

    lawful_basis = bases.get(interactive_prompt("\n[GDPR Art.6] Lawful basis", "2"), "Contract")
    purpose = interactive_prompt("Processing purpose", "Data analysis")
    confirmed = confirm_yes_no("Data owner consents?", True)
    gov.consent_recorded(purpose, lawful_basis, confirmed)

    if confirm_yes_no("\n[CCPA §1798.120] Will data be sold/shared with third parties?", False):
        optout = confirm_yes_no("Has subject opted OUT?", True)
        gov.consent_event("CCPA_SALE_OPTOUT", {"opted_out": optout})
        if optout:
            logger.info("Opt-out recorded.")

    pii_strategy = "retain"
    if pii_findings:
        print(f"\n[PRIVACY] {len(pii_findings)} PII field(s):")
        for f in pii_findings:
            special = " SPECIAL CATEGORY" if f["special_category"] else ""
            print(f"  - {f['field']}{special}")
        print("\n  1.Mask (SHA-256)  2.Drop  3.Retain (with consent)")
        pii_strategy = {"1": "mask", "2": "drop", "3": "retain"}.get(
            interactive_prompt("Choice", "1"), "mask"
        )

    print("\n[GDPR Art.5(1)(e)] Retention:  1.30d  2.90d  3.1yr  4.2yr  5.5yr  6.Indefinite")
    ret_map = {"1": 30, "2": 90, "3": 365, "4": 730, "5": 1825, "6": None}
    retention_days = ret_map.get(interactive_prompt("Choice", "3"), 365)
    gov.retention_policy(
        f"Retain {retention_days} days" if retention_days else "Indefinite",
        retention_days,
    )

    drop_cols: list[str] = []
    if confirm_yes_no("\n[GDPR Art.5(1)(c)] Drop specific columns?", False):
        drop_cols = [c.strip() for c in input("Columns (comma-sep): ").split(",") if c.strip()]

    return {
        "lawful_basis": lawful_basis,
        "purpose": purpose,
        "pii_strategy": pii_strategy,
        "retention_days": retention_days,
        "drop_cols": drop_cols,
    }
