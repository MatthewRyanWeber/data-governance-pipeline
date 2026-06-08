"""
Synthetic data generator — creates realistic fake data mirroring a real DataFrame's schema.

Layer 3 — imports from Layer 1 (governance_logger).

Revision history
────────────────
1.0   2026-06-07   Initial extraction from pipeline_v3.py.
"""

import logging
from typing import TYPE_CHECKING

import pandas as pd

if TYPE_CHECKING:
    from pipeline.governance_logger import GovernanceLogger

logger = logging.getLogger(__name__)


class SyntheticDataGenerator:
    """
    Generates realistic fake data that mirrors the schema and statistical
    profile of a real DataFrame.  Useful for creating dev/test datasets
    without exposing real PII.

    Uses the Faker library for locale-aware realistic values (names,
    emails, addresses, phone numbers, dates, etc.).

    Features
    --------
    - Infers column semantics from column names (email, name, phone, etc.)
    - Preserves numeric ranges (min/max) from the source DataFrame
    - Preserves categorical distributions (value frequencies)
    - Respects date ranges
    - Supports multiple locales

    Quick-start
    -----------
        from pipeline.quality import SyntheticDataGenerator
        gen = SyntheticDataGenerator(gov)
        df_fake = gen.generate(df_real, n_rows=1000)
        gen.save(df_fake, "synthetic_employees.csv")

    Parameters
    ----------
    gov    : GovernanceLogger
    locale : str   Faker locale, e.g. "en_US", "de_DE", "ja_JP".
                   Defaults to "en_US".
    """

    _PII_PATTERNS: dict[str, str] = {
        "email":     "email",
        "mail":      "email",
        "name":      "name",
        "first":     "first_name",
        "last":      "last_name",
        "phone":     "phone_number",
        "mobile":    "phone_number",
        "address":   "address",
        "street":    "street_address",
        "city":      "city",
        "state":     "state",
        "zip":       "postcode",
        "postal":    "postcode",
        "country":   "country",
        "company":   "company",
        "username":  "user_name",
        "url":       "url",
        "ip":        "ipv4",
        "ssn":       "ssn",
        "dob":       "date_of_birth",
        "birth":     "date_of_birth",
        "gender":    "random_element",
        "uuid":      "uuid4",
    }

    def __init__(self, gov: "GovernanceLogger", locale: str = "en_US") -> None:
        self.gov = gov
        try:
            from faker import Faker as _Faker  # pylint: disable=import-outside-toplevel
            self._fake = _Faker(locale)
        except ImportError as exc:
            raise RuntimeError("SyntheticDataGenerator requires: pip install faker") from exc

    def _faker_value(self, col: str, profile: dict) -> object:
        """Return a single synthetic value for one column."""
        col_lower = col.lower()

        # Match column name to a Faker method
        for pattern, method in self._PII_PATTERNS.items():
            if pattern in col_lower:
                if method == "random_element":
                    return self._fake.random_element(["M", "F", "Non-binary"])
                return getattr(self._fake, method)()

        # Numeric column — sample uniformly within the observed range
        if profile.get("dtype") in ("int64", "Int64", "float64", "float32"):
            lo = profile.get("min", 0)
            hi = profile.get("max", 100)
            if profile["dtype"] in ("int64", "Int64"):
                return self._fake.random_int(min=int(lo), max=int(hi))
            return round(self._fake.pyfloat(min_value=float(lo), max_value=float(hi)), 4)

        # Boolean
        if profile.get("dtype") in ("bool", "boolean"):
            return self._fake.boolean()

        # Datetime
        if "datetime" in profile.get("dtype", ""):
            return self._fake.date_time_between(
                start_date=profile.get("min", "-2y"),
                end_date=profile.get("max",  "now"),
            ).isoformat()

        # Categorical — sample from observed values weighted by frequency
        if profile.get("categories"):
            cats    = list(profile["categories"].keys())
            weights = list(profile["categories"].values())
            total   = sum(weights) or 1
            weights = [w / total for w in weights]
            import random as _random  # pylint: disable=import-outside-toplevel
            return _random.choices(cats, weights=weights, k=1)[0]

        # Default: realistic-looking sentence fragment
        return self._fake.word()

    def _profile_column(self, df: "pd.DataFrame", col: str) -> dict:
        """Build a statistical profile for one column."""
        series  = df[col]
        dtype   = str(series.dtype)
        profile = {"dtype": dtype}

        if dtype in ("int64", "Int64", "float64", "float32"):
            profile["min"] = float(series.min()) if not series.isna().all() else 0
            profile["max"] = float(series.max()) if not series.isna().all() else 100

        elif "datetime" in dtype:
            profile["min"] = series.min().isoformat() if not series.isna().all() else "-2y"
            profile["max"] = series.max().isoformat() if not series.isna().all() else "now"

        elif dtype == "object":
            vc = series.value_counts()
            if len(vc) <= 30:
                profile["categories"] = vc.to_dict()

        return profile

    def generate(self, df_source: "pd.DataFrame", n_rows: int = 1000) -> "pd.DataFrame":
        """
        Generate a synthetic DataFrame with the same schema as ``df_source``.

        Parameters
        ----------
        df_source : pd.DataFrame   Template DataFrame (schema + statistics).
        n_rows    : int            Number of synthetic rows to generate.

        Returns
        -------
        pd.DataFrame  Synthetic data.
        """
        profiles = {col: self._profile_column(df_source, col) for col in df_source.columns}
        rows = [
            {col: self._faker_value(col, profiles[col]) for col in df_source.columns}
            for _ in range(n_rows)
        ]
        df_fake = pd.DataFrame(rows, columns=list(df_source.columns))
        self.gov.transformation_applied("SYNTHETIC_DATA_GENERATED", {
            "n_rows":  n_rows,
            "columns": list(df_source.columns),
        })
        logger.info("[SyntheticData] Generated %d rows with %d columns",
                    n_rows, len(df_source.columns))
        return df_fake

    def save(self, df: "pd.DataFrame", path: str, fmt: str = "csv") -> str:
        """
        Save the synthetic DataFrame to disk.

        Parameters
        ----------
        df   : pd.DataFrame
        path : str   Output file path.
        fmt  : str   "csv" | "json" | "parquet"  (default "csv")
        """
        if fmt == "csv":
            df.to_csv(path, index=False)
        elif fmt == "json":
            df.to_json(path, orient="records", lines=True)
        elif fmt == "parquet":
            df.to_parquet(path, index=False)
        else:
            raise ValueError(f"Unsupported format: {fmt!r}")
        self.gov.transformation_applied("SYNTHETIC_DATA_SAVED", {"path": path, "fmt": fmt})
        logger.info("[SyntheticData] Saved %s (%s format)", path, fmt)
        return path
