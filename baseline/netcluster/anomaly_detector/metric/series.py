"""Small parsing and robust-statistics helpers shared by metric detection."""

from __future__ import annotations

from datetime import datetime
import math
from statistics import median


NULL_TOKENS = {"", "NULL", "null", "NaN", "nan", "None", "none"}


def parse_timestamp(value: str) -> datetime | None:
    text = value.strip().strip('"')
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def parse_number(value: str | None) -> float | None:
    if value is None:
        return None
    text = value.strip().strip('"')
    if text in NULL_TOKENS:
        return None
    try:
        number = float(text)
    except ValueError:
        return None
    return number if math.isfinite(number) else None


def robust_scale(values: list[float], center: float) -> float:
    deviations = [abs(value - center) for value in values]
    return 1.4826 * median(deviations) if deviations else 0.0


def autocorrelation(values: list[float], lag: int) -> float:
    left = values[:-lag]
    right = values[lag:]
    if len(left) < 2:
        return 0.0
    left_mean = sum(left) / len(left)
    right_mean = sum(right) / len(right)
    numerator = sum((a - left_mean) * (b - right_mean) for a, b in zip(left, right))
    left_den = math.sqrt(sum((a - left_mean) ** 2 for a in left))
    right_den = math.sqrt(sum((b - right_mean) ** 2 for b in right))
    denominator = left_den * right_den
    return numerator / denominator if denominator > 1e-12 else 0.0
