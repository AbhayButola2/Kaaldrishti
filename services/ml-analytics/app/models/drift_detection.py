"""
Drift detector using CUSUM (Cumulative Sum) change-point detection.

Detects distributional drift in a time-series of metric values compared to
a known baseline (mean, stddev). Returns:
  - drift_detected: bool
  - magnitude: normalized CUSUM statistic
  - confidence: calibrated probability
  - change_point_idx: index of first detected change point (-1 if none)
  - detector_type: "cusum"

References:
  - Page (1954) "Continuous Inspection Schemes"
  - ADWIN: Bifet & Gavalda (2007) "Learning from Time-Changing Data with Adaptive Windowing"

PROTOTYPE NOTE: Only CUSUM is implemented. ADWIN requires a stream API;
adding it here is deferred. See docs/architecture/deferred_work.md.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List

import numpy as np


@dataclass
class DriftResult:
    drift_detected: bool
    magnitude: float
    confidence: float
    change_point_idx: int
    detector_type: str


class DriftDetector:
    """
    CUSUM-based change-point detector.

    Computes cumulative sum of standardized deviations from baseline.
    Declares drift when CUSUM exceeds a threshold (default: 5 sigma-equivalent).
    """

    def __init__(self, threshold: float = 5.0, k: float = 0.5) -> None:
        """
        threshold: CUSUM threshold in sigma units (h parameter).
        k:         allowable slack in sigma units (k parameter).
        """
        self.threshold = threshold
        self.k = k

    def evaluate(
        self,
        values: List[float],
        baseline_mean: float,
        baseline_stddev: float,
    ) -> DriftResult:
        """
        Run CUSUM on values against the baseline distribution.

        Returns a DriftResult with drift_detected=True if the CUSUM statistic
        exceeds self.threshold at any point in the series.
        """
        if not values:
            return DriftResult(False, 0.0, 0.0, -1, "cusum")
        if baseline_stddev <= 0.0:
            baseline_stddev = 1.0  # Guard against division by zero.

        arr = np.array(values, dtype=float)

        # Standardize values.
        z = (arr - baseline_mean) / baseline_stddev

        # Two-sided CUSUM.
        cusum_pos = np.zeros(len(z) + 1)
        cusum_neg = np.zeros(len(z) + 1)
        change_point = -1
        max_stat = 0.0

        for i, zi in enumerate(z):
            cusum_pos[i + 1] = max(0.0, cusum_pos[i] + zi - self.k)
            cusum_neg[i + 1] = max(0.0, cusum_neg[i] - zi - self.k)
            stat = max(cusum_pos[i + 1], cusum_neg[i + 1])
            if stat > max_stat:
                max_stat = stat
            if stat > self.threshold and change_point == -1:
                change_point = i

        drift_detected = change_point >= 0
        magnitude = float(min(1.0, max_stat / (self.threshold * 2.0)))
        confidence = min(0.95, 0.5 + magnitude * 0.4) if drift_detected else 0.5

        return DriftResult(
            drift_detected=drift_detected,
            magnitude=magnitude,
            confidence=confidence,
            change_point_idx=change_point,
            detector_type="cusum",
        )
