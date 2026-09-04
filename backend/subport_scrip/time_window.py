"""
time_window.py
---------------
Multi-Time-Window Feature Engineering for CIC-IDS2017 flow-level data.

SINGLE SOURCE OF TRUTH: `build_multi_time_window_features()` is the ONLY
place time-window aggregation logic lives. Both train_cicids2017.py
(training) and any future inference code MUST call this exact function on
their flow-level DataFrame before it touches the model -- duplicating this
logic anywhere else is how training and inference features silently drift
apart (Feature Mismatch).

Time windows: 2 seconds ("2s", the primary/finer axis) and 10 seconds
("10s", merged in as wider context), producing ONE ROW PER 2-SECOND WINDOW
with both tw2_* and tw10_* aggregate columns.

Data-leakage guard: Flow ID, Source/Destination IP, ports, and the raw
per-flow Label are NEVER used as aggregation features. Timestamp is used
ONLY to floor/bucket flows into windows, never as a feature value itself.
"""

import logging
import re
from typing import Iterable, List, Optional

import numpy as np
import pandas as pd

logger = logging.getLogger("time_window")

# The two windows this module builds, in seconds. 2s is the primary/join
# axis; 10s is merged in as wider context (see build_multi_time_window_features).
TIME_WINDOWS_SECONDS = [2, 10]

# Columns that must NEVER be used as aggregation features, regardless of
# what's present in the incoming DataFrame or what the caller passes in
# `feature_columns` (data-leakage guard -- enforced, not just documented).
# NOTE: "Destination Port"/"Dst Port" is intentionally NOT here -- it IS one
# of the official 78 CICIDS2017 feature columns (config.cic_feature_columns[0]).
# Only the SOURCE port (an ephemeral, not-predictive value) is excluded.
_NEVER_AGGREGATE_COLUMNS = {
    "Flow ID", "Source IP", "Src IP", "Destination IP", "Dst IP",
    "Source Port", "Src Port",
    "Timestamp", "Label", "Protocol",
}

_AGG_FUNCS = ["mean", "max", "sum"]

# Attack-family severity priority, MOST severe first. Resolves a time
# window containing more than one attack family: the window's label is
# whichever family here appears EARLIEST in this list (i.e. most severe),
# even if it's a single flow among many of a less severe type or BENIGN.
# BENIGN is intentionally absent -- a window is only BENIGN if no attack
# family appears in it at all.
ATTACK_FAMILY_SEVERITY_PRIORITY = [
    "Heartbleed",
    "Infiltration",
    "Botnet",
    "DDoS",
    "DoS",
    "WebAttack",
    "BruteForce",
    "PortScan",
]


def _to_snake(feature_name: str) -> str:
    """'Flow Duration' -> 'flow_duration', 'Flow Bytes/s' -> 'flow_bytes_s'."""
    s = feature_name.strip().lower()
    s = re.sub(r"[^a-z0-9]+", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    return s


def _parse_timestamp(series: pd.Series) -> pd.Series:
    """
    Robustly parses CICIDS2017's Timestamp column, which is NOT
    consistently formatted across the dataset's daily CSV files (commonly
    'DD/MM/YYYY HH:MM' or 'DD/MM/YYYY HH:MM:SS'). Tries known formats in
    order before falling back to pandas' general inference; anything still
    unparseable becomes NaT and is DROPPED by the caller -- never guessed
    or defaulted to some fabricated time.
    """
    if pd.api.types.is_datetime64_any_dtype(series):
        return series

    candidate_formats = [
        "%d/%m/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M",
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M",
    ]
    raw = series.astype(str).str.strip()
    parsed = pd.Series(pd.NaT, index=series.index, dtype="datetime64[ns]")
    remaining_mask = pd.Series(True, index=series.index)

    for fmt in candidate_formats:
        if not remaining_mask.any():
            break
        attempt = pd.to_datetime(raw[remaining_mask], format=fmt, errors="coerce")
        newly_parsed = attempt.notna()
        idx = attempt.index[newly_parsed]
        parsed.loc[idx] = attempt.loc[idx]
        remaining_mask.loc[idx] = False

    if remaining_mask.any():
        fallback = pd.to_datetime(raw[remaining_mask], errors="coerce")
        parsed.loc[fallback.index] = fallback

    n_unparsed = int(parsed.isna().sum())
    if n_unparsed:
        logger.warning(
            "time_window: %d/%d Timestamp value(s) could not be parsed and "
            "will be dropped (never guessed).", n_unparsed, len(series),
        )
    return parsed


def _resolve_window_label(labels_in_window: Iterable[str]) -> str:
    """
    Labeling Policy for one time window:
      - only BENIGN present         -> BENIGN
      - any attack family present   -> the MOST SEVERE attack family present
        (ATTACK_FAMILY_SEVERITY_PRIORITY), even if outnumbered by BENIGN or
        less-severe attack flows in the same window.
    """
    present = set(labels_in_window)
    for family in ATTACK_FAMILY_SEVERITY_PRIORITY:
        if family in present:
            return family
    return "BENIGN"


def _aggregate_one_window(df: pd.DataFrame, window_seconds: int, feature_columns: List[str]) -> pd.DataFrame:
    """Floors Timestamp to `window_seconds`, groups, and aggregates mean/max/sum
    per feature plus a flow_count. Returns one row per bucket, columns
    prefixed tw{window_seconds}_."""
    prefix = f"tw{window_seconds}"
    floored = df["Timestamp"].dt.floor(f"{window_seconds}s")
    grouped = df.groupby(floored)

    stats = grouped[feature_columns].agg(_AGG_FUNCS)
    stats.columns = [f"{prefix}_{_to_snake(col)}_{stat}" for col, stat in stats.columns]

    flow_count = grouped.size().rename(f"{prefix}_flow_count")
    window_label = grouped["Label"].apply(_resolve_window_label).rename(f"{prefix}_window_label")

    result = pd.concat([flow_count, stats, window_label], axis=1)
    result.index.name = f"{prefix}_bucket"
    return result.reset_index()


def build_multi_time_window_features(
    df: pd.DataFrame,
    feature_columns: Optional[List[str]] = None,
    timestamp_col: str = "Timestamp",
    label_col: str = "Label",
) -> pd.DataFrame:
    
    if timestamp_col not in df.columns:
        raise ValueError(f"'{timestamp_col}' column not found in input DataFrame.")
    
    # ทำให้ label_col เป็นทางเลือก (Optional) ถ้าไม่มีในโหมด Inference ให้สร้างคอลัมน์สำรองชั่วคราวโดยไม่ต้องบังคับว่าต้องมีจริง
    if label_col not in df.columns:
        df = df.copy()
        df[label_col] = "UNKNOWN"  # หรือค่าว่างเปล่า เพื่อให้ฟังก์ชันเดินต่อได้
    

    work = df.copy()
    work[timestamp_col] = _parse_timestamp(work[timestamp_col])
    work = work.dropna(subset=[timestamp_col])
    if work.empty:
        raise ValueError("No rows with a parseable Timestamp remain -- cannot build time windows.")

    if timestamp_col != "Timestamp":
        work = work.rename(columns={timestamp_col: "Timestamp"})
    if label_col != "Label":
        work = work.rename(columns={label_col: "Label"})

    if feature_columns is None:
        feature_columns = [
            c for c in work.columns
            if c not in _NEVER_AGGREGATE_COLUMNS
            and pd.api.types.is_numeric_dtype(work[c])
        ]
        logger.info(
            "time_window: no feature_columns given, auto-detected %d numeric column(s).",
            len(feature_columns),
        )
    else:
        missing = [c for c in feature_columns if c not in work.columns]
        if missing:
            raise ValueError(f"feature_columns not found in input DataFrame: {missing}")

    # Explicit leakage guard, enforced even if the caller passed
    # feature_columns manually and made a mistake.
    leaked = _NEVER_AGGREGATE_COLUMNS.intersection(feature_columns)
    if leaked:
        raise ValueError(
            f"Refusing to aggregate leakage-prone column(s) as features: {sorted(leaked)}. "
            f"Flow ID / IPs / Ports / Timestamp / Label must never be ML features."
        )

    work[feature_columns] = work[feature_columns].apply(pd.to_numeric, errors="coerce")
    work[feature_columns] = work[feature_columns].replace([np.inf, -np.inf], np.nan).fillna(0.0)

    window_frames = {w: _aggregate_one_window(work, w, feature_columns) for w in TIME_WINDOWS_SECONDS}

    # Merge on the 2s window as the primary time axis: every 2s bucket
    # looks up the 10s bucket it falls inside and merges that bucket's
    # stats in alongside it.
    base = window_frames[2].copy()
    base["_10s_bucket_key"] = base["tw2_bucket"].dt.floor("10s")

    other = window_frames[10].rename(columns={"tw10_bucket": "_10s_bucket_key"})

    merged = base.merge(other, on="_10s_bucket_key", how="left")
    merged = merged.drop(columns=["_10s_bucket_key"])
    merged = merged.rename(columns={"tw2_bucket": "window_start"})

    # Final window label: the 2s (tighter, more precise) bucket's own label
    # takes precedence over the wider 10s context.
    merged["window_label"] = merged["tw2_window_label"]
    merged = merged.drop(columns=["tw2_window_label", "tw10_window_label"])

    logger.info(
        "time_window: built %d time-window row(s) from %d flow(s), %d feature column(s) aggregated per window.",
        len(merged), len(work), len(feature_columns),
    )
    return merged


if __name__ == "__main__":
    # Tiny smoke test with synthetic data -- run `python time_window.py`.
    logging.basicConfig(level=logging.INFO)
    rng = pd.date_range("2017-07-07 09:00:00", periods=30, freq="700ms")
    demo = pd.DataFrame({
        "Timestamp": rng.strftime("%d/%m/%Y %H:%M:%S"),
        "Flow Duration": np.random.uniform(10, 1000, size=30),
        "Total Fwd Packets": np.random.randint(1, 20, size=30),
        "Label": ["BENIGN"] * 25 + ["PortScan"] * 3 + ["DDoS"] * 2,
    })
    out = build_multi_time_window_features(demo, feature_columns=["Flow Duration", "Total Fwd Packets"])
    print(out[["window_start", "tw2_flow_count", "tw10_flow_count", "window_label"]])
