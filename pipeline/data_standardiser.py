"""
Normalises common data formats to consistent, interoperable standards.

Rules: phone_e164, date_iso8601, country_iso2, bool_normalize, upper, lower, strip, title.

Layer 2 — imports from Layer 0 (constants), Layer 1 (governance_logger).
"""

import logging
from typing import TYPE_CHECKING

from pipeline.constants import HAS_PHONENUMBERS

if TYPE_CHECKING:
    import pandas as pd
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class DataStandardiser:
    """
    Applies standardisation rules to DataFrame columns.

    Quick-start
    -----------
        from pipeline.data_standardiser import DataStandardiser
        ds = DataStandardiser(gov)
        df = ds.standardise(df, {"phone": "phone_e164", "country": "country_iso2"})
    """

    COUNTRY_MAP: dict[str, str] = {
        "united states": "US", "usa": "US", "us": "US", "america": "US",
        "united kingdom": "GB", "uk": "GB", "great britain": "GB",
        "canada": "CA", "germany": "DE", "france": "FR", "italy": "IT",
        "spain": "ES", "netherlands": "NL", "belgium": "BE",
        "australia": "AU", "new zealand": "NZ", "japan": "JP",
        "china": "CN", "india": "IN", "brazil": "BR", "mexico": "MX",
        "south korea": "KR", "korea": "KR", "switzerland": "CH",
        "sweden": "SE", "norway": "NO", "denmark": "DK", "finland": "FI",
        "poland": "PL", "portugal": "PT", "ireland": "IE", "austria": "AT",
    }

    def __init__(self, gov: "GovernanceLogger") -> None:
        self.gov = gov

    def standardise(
        self,
        df: "pd.DataFrame",
        rules: dict[str, str],
        default_phone_region: str = "US",
    ) -> "pd.DataFrame":
        """Apply standardisation rules to the specified columns."""
        import pandas as pd

        for col, rule in rules.items():
            if col not in df.columns:
                continue

            changed = 0

            if rule == "phone_e164":
                df[col], changed = self._normalise_phones(df[col], default_phone_region)

            elif rule == "date_iso8601":
                original = df[col].copy()
                parsed = pd.to_datetime(df[col], errors="coerce")
                valid = parsed.notna()
                df[col] = parsed.dt.strftime("%Y-%m-%d").where(valid, other=df[col])
                changed = int((df[col] != original).sum())

            elif rule == "country_iso2":
                df[col], changed = self._normalise_countries(df[col])

            elif rule == "bool_normalize":
                bool_map = {
                    "yes": "True", "1": "True", "true": "True",
                    "no": "False", "0": "False", "false": "False",
                }
                original = df[col].copy()
                mask = df[col].notna()
                keys = df.loc[mask, col].astype(str).str.strip().str.lower()
                mapped = keys.map(bool_map)
                df.loc[mask, col] = mapped.fillna(df.loc[mask, col])
                changed = int((df[col] != original).sum())

            elif rule in ("upper", "lower", "strip", "title"):
                original = df[col].copy()
                mask = df[col].notna()
                df.loc[mask, col] = getattr(
                    df.loc[mask, col].astype(str).str, rule
                )()
                changed = int((df[col] != original).sum())

            self.gov.standardisation_applied(col, rule, changed)

        return df

    def _normalise_phones(
        self, series: "pd.Series", region: str,
    ) -> tuple["pd.Series", int]:
        import pandas as pd

        if not HAS_PHONENUMBERS:
            logger.warning("phonenumbers library not installed — phone_e164 normalization skipped")
            return series.copy(), 0
        import phonenumbers

        def _parse_one(val):
            if pd.isna(val):
                return val
            try:
                parsed = phonenumbers.parse(str(val), region)
                return phonenumbers.format_number(
                    parsed, phonenumbers.PhoneNumberFormat.E164,
                )
            except Exception as exc:
                logger.debug("Could not parse phone value: %s", exc)
                return val

        result = series.apply(_parse_one)
        mask = series.notna()
        changed = int((result[mask].astype(str) != series[mask].astype(str)).sum())
        return result, changed

    def _normalise_countries(
        self, series: "pd.Series",
    ) -> tuple["pd.Series", int]:
        mask = series.notna()
        original_str = series.loc[mask].astype(str)
        keys = original_str.str.strip().str.lower()
        mapped = keys.map(self.COUNTRY_MAP)
        result = series.copy()
        result.loc[mask] = mapped.fillna(original_str)
        changed = int((result.loc[mask] != original_str).sum())
        return result, changed
