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
                df[col] = (
                    pd.to_datetime(df[col], errors="coerce")
                    .dt.strftime("%Y-%m-%d")
                    .where(pd.to_datetime(df[col], errors="coerce").notna(), other=df[col])
                )
                changed = int((df[col] != original).sum())

            elif rule == "country_iso2":
                df[col], changed = self._normalise_countries(df[col])

            elif rule == "bool_normalize":
                bool_map = {
                    "yes": "True", "1": "True", "true": "True",
                    "no": "False", "0": "False", "false": "False",
                }
                original = df[col].copy()
                df[col] = df[col].apply(
                    lambda x, _m=bool_map: _m.get(str(x).strip().lower(), x)
                    if pd.notna(x) else x
                )
                changed = int((df[col] != original).sum())

            elif rule in ("upper", "lower", "strip", "title"):
                original = df[col].copy()
                fn = {"upper": str.upper, "lower": str.lower,
                      "strip": str.strip, "title": str.title}[rule]
                df[col] = df[col].apply(
                    lambda x, _fn=fn: _fn(str(x)) if pd.notna(x) else x
                )
                changed = int((df[col] != original).sum())

            self.gov.standardisation_applied(col, rule, changed)

        return df

    def _normalise_phones(
        self, series: "pd.Series", region: str,
    ) -> tuple["pd.Series", int]:
        import pandas as pd

        changed = 0
        results = []
        if HAS_PHONENUMBERS:
            import phonenumbers
        for val in series:
            if pd.isna(val):
                results.append(val)
                continue
            if HAS_PHONENUMBERS:
                try:
                    parsed = phonenumbers.parse(str(val), region)
                    e164 = phonenumbers.format_number(
                        parsed, phonenumbers.PhoneNumberFormat.E164,
                    )
                    if e164 != str(val):
                        changed += 1
                    results.append(e164)
                except Exception as exc:
                    logger.debug("Could not parse phone '%s': %s", val, exc)
                    results.append(val)
            else:
                results.append(val)
        return pd.Series(results, index=series.index), changed

    def _normalise_countries(
        self, series: "pd.Series",
    ) -> tuple["pd.Series", int]:
        import pandas as pd

        changed = 0
        results = []
        for val in series:
            if pd.isna(val):
                results.append(val)
                continue
            normalised = self.COUNTRY_MAP.get(str(val).strip().lower(), str(val))
            if normalised != str(val):
                changed += 1
            results.append(normalised)
        return pd.Series(results, index=series.index), changed
