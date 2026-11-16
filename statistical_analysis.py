"""Small-sample-friendly descriptive statistics for binary experiment metrics."""
from __future__ import annotations

import math
from typing import Optional


def wilson_interval(successes: int, trials: int, z: float = 1.959963984540054) -> Optional[tuple[float, float]]:
    """Return a two-sided Wilson score interval as proportions, or None."""
    if trials <= 0:
        return None
    if successes < 0 or successes > trials:
        raise ValueError("successes must be between zero and trials")
    p = successes / trials
    denom = 1 + z * z / trials
    center = (p + z * z / (2 * trials)) / denom
    margin = z * math.sqrt((p * (1 - p) / trials) + (z * z / (4 * trials * trials))) / denom
    return max(0.0, center - margin), min(1.0, center + margin)


def describe_binary(successes: int, trials: int) -> dict:
    interval = wilson_interval(successes, trials)
    return {
        "successes": successes,
        "trials": trials,
        "rate_pct": (100 * successes / trials) if trials else None,
        "ci95_low_pct": (100 * interval[0]) if interval else None,
        "ci95_high_pct": (100 * interval[1]) if interval else None,
    }
