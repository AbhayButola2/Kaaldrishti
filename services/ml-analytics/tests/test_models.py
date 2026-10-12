"""
Tests for the ML analytics models.

Covers all five model interfaces without requiring Go or Rust to be running.
The gRPC layer is tested separately (see tests/test_grpc.py).
"""
from __future__ import annotations

import pytest
import numpy as np


# ---------------------------------------------------------------------------
# Blast radius (PPR)
# ---------------------------------------------------------------------------

class TestBlastRadiusScorer:
    from app.models.blast_radius import BlastRadiusScorer

    def _make_proto_node(self, node_id, node_type=7, confidence=0.9, sensitivity=None):
        class N:
            pass
        n = N()
        n.node_id = node_id
        n.node_type = node_type
        n.confidence = confidence
        n.recency_decay = 1.0
        props = {}
        if sensitivity:
            props["asset.sensitivity"] = sensitivity
        n.properties = props
        return n

    def _make_proto_edge(self, src, dst, confidence=0.8):
        class E:
            pass
        e = E()
        e.src_node_id = src
        e.dst_node_id = dst
        e.confidence = confidence
        return e

    def test_no_crown_jewels_returns_zero_score(self):
        from app.models.blast_radius import BlastRadiusScorer
        scorer = BlastRadiusScorer()
        nodes = [
            self._make_proto_node("p1", node_type=1),
            self._make_proto_node("h1", node_type=3),
        ]
        edges = [self._make_proto_edge("p1", "h1")]
        result = scorer.compute("p1", nodes, edges)
        assert result.overall_score == 0.0
        assert result.crown_jewel_scores == {}

    def test_crown_jewel_reachable_scores_nonzero(self):
        from app.models.blast_radius import BlastRadiusScorer
        scorer = BlastRadiusScorer()
        nodes = [
            self._make_proto_node("proc1", node_type=4),
            self._make_proto_node("cj1", node_type=7, sensitivity="crown_jewel"),
        ]
        edges = [self._make_proto_edge("proc1", "cj1")]
        result = scorer.compute("proc1", nodes, edges)
        assert result.overall_score > 0.0
        assert "cj1" in result.crown_jewel_scores

    def test_empty_nodes_returns_empty(self):
        from app.models.blast_radius import BlastRadiusScorer
        scorer = BlastRadiusScorer()
        result = scorer.compute("x", [], [])
        assert result.overall_score == 0.0


# ---------------------------------------------------------------------------
# Drift detection (CUSUM)
# ---------------------------------------------------------------------------

class TestDriftDetector:
    def test_no_drift_in_stable_series(self):
        from app.models.drift_detection import DriftDetector
        detector = DriftDetector(threshold=5.0, k=0.5)
        values = [0.0, 0.1, -0.1, 0.05, -0.05, 0.0] * 5
        result = detector.evaluate(values, baseline_mean=0.0, baseline_stddev=1.0)
        assert not result.drift_detected
        assert result.change_point_idx == -1

    def test_drift_detected_on_step_change(self):
        from app.models.drift_detection import DriftDetector
        detector = DriftDetector(threshold=5.0, k=0.5)
        # First 10 values: near 0. Next 10: near 10 (10-sigma shift).
        values = [0.0] * 10 + [10.0] * 10
        result = detector.evaluate(values, baseline_mean=0.0, baseline_stddev=1.0)
        assert result.drift_detected
        assert result.change_point_idx >= 10
        assert result.magnitude > 0.0

    def test_zero_stddev_does_not_raise(self):
        from app.models.drift_detection import DriftDetector
        detector = DriftDetector()
        result = detector.evaluate([1.0, 2.0, 3.0], baseline_mean=1.0, baseline_stddev=0.0)
        assert isinstance(result.drift_detected, bool)

    def test_empty_values_returns_no_drift(self):
        from app.models.drift_detection import DriftDetector
        detector = DriftDetector()
        result = detector.evaluate([], baseline_mean=0.0, baseline_stddev=1.0)
        assert not result.drift_detected


# ---------------------------------------------------------------------------
# Intent lineage (cosine drift)
# ---------------------------------------------------------------------------

class TestIntentLineageScorer:
    def test_identical_strings_near_zero_drift(self):
        from app.models.intent_lineage import IntentLineageScorer
        scorer = IntentLineageScorer()
        score, conf, explanation = scorer.score("rotate credentials tokens", "rotate credentials tokens")
        assert score < 0.3, f"Expected low drift for identical text, got {score}"

    def test_completely_different_strings_high_drift(self):
        from app.models.intent_lineage import IntentLineageScorer
        scorer = IntentLineageScorer()
        score, conf, explanation = scorer.score("rotate password credentials secrets", "read file data exfiltrate download")
        assert score > 0.0, "Expected nonzero drift for different texts"

    def test_empty_inputs_return_zero(self):
        from app.models.intent_lineage import IntentLineageScorer
        scorer = IntentLineageScorer()
        score, conf, explanation = scorer.score("", "")
        assert score == 0.0


# ---------------------------------------------------------------------------
# Next attack forecaster
# ---------------------------------------------------------------------------

class TestNextAttackForecaster:
    def test_known_technique_returns_predictions(self):
        from app.models.next_attack import NextAttackForecaster
        forecaster = NextAttackForecaster()
        preds = forecaster.forecast(["T1078"], top_k=3)
        assert len(preds) <= 3
        for p in preds:
            assert 0.0 <= p.probability <= 1.0
            assert p.technique_id.startswith("T")

    def test_empty_sequence_returns_defaults(self):
        from app.models.next_attack import NextAttackForecaster
        forecaster = NextAttackForecaster()
        preds = forecaster.forecast([], top_k=3)
        assert len(preds) > 0

    def test_unknown_technique_returns_defaults(self):
        from app.models.next_attack import NextAttackForecaster
        forecaster = NextAttackForecaster()
        preds = forecaster.forecast(["TXXXX-unknown"], top_k=2)
        assert len(preds) > 0
