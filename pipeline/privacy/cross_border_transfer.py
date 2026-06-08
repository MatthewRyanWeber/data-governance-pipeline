"""
GDPR Chapter V cross-border data transfer detection and logging.

Evaluates source/destination jurisdiction pairs and logs the applicable
legal transfer mechanism (SCC, BCR, Adequacy Decision, etc.).

Layer 3 — imports from Layer 0 (constants), Layer 1 (governance_logger).
"""

import logging
from typing import TYPE_CHECKING

from pipeline.constants import EU_EEA_COUNTRY_CODES, ADEQUATE_COUNTRIES

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class CrossBorderTransferLogger:
    """
    Detects and logs cross-border data transfers under GDPR Chapter V.

    Quick-start
    -----------
        from pipeline.privacy import CrossBorderTransferLogger
        xfer = CrossBorderTransferLogger(gov)
        xfer.check_and_log("US", "DE", "SCC")
    """

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov

    def check_and_log(
        self,
        source_country: str,
        dest_country: str,
        configured_safeguard: str = "SCC",
    ) -> str:
        """Evaluate the transfer scenario and log the appropriate event."""
        src = source_country.upper().strip()
        dst = dest_country.upper().strip()

        if src == dst:
            transfer_type = "DOMESTIC"
            safeguard = "No transfer — same jurisdiction"
        elif src in EU_EEA_COUNTRY_CODES and dst in EU_EEA_COUNTRY_CODES:
            transfer_type = "INTRA_EU"
            safeguard = "EU/EEA intra-zone transfer — no restrictions"
        elif dst in ADEQUATE_COUNTRIES:
            transfer_type = "ADEQUACY_DECISION"
            safeguard = f"Adequacy Decision (GDPR Art. 45) — {dst}"
        elif configured_safeguard.upper() in ("SCC", "STANDARD_CONTRACTUAL_CLAUSES"):
            transfer_type = "SCC"
            safeguard = "Standard Contractual Clauses (GDPR Art. 46(2)(c))"
        elif configured_safeguard.upper() in ("BCR", "BINDING_CORPORATE_RULES"):
            transfer_type = "BCR"
            safeguard = "Binding Corporate Rules (GDPR Art. 47)"
        else:
            transfer_type = "UNKNOWN_SAFEGUARD"
            safeguard = f"No recognised safeguard configured: {configured_safeguard!r}"

        self.gov.transfer_logged(src, dst, safeguard, transfer_type)
        logger.info("[TRANSFER] %s → %s | %s | %s", src, dst, transfer_type, safeguard)
        return transfer_type
