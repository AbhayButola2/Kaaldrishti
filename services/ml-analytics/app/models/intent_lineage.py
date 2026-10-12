"""
Intent lineage scorer — cosine-distance between declared scope and actual action.

THIS IS NOT PILLAR 5. This is Kaaladrishti's internal intent drift tracker:
it measures how much an agent's actual action deviates from its declared scope.
It returns an advisory drift score only. No execution decision is made here.

Algorithm:
  1. Encode declared_scope_text and actual_action_text as TF-IDF vectors.
  2. Compute cosine distance between the two vectors.
  3. drift_score = cosine_distance ∈ [0, 1] (0 = identical, 1 = orthogonal).
"""
from __future__ import annotations

from typing import Tuple

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


class IntentLineageScorer:
    """
    Cosine-similarity drift scorer for intent lineage tracking.

    PROTOTYPE NOTE: uses TF-IDF for text representation. A production model
    would use a fine-tuned sentence encoder (e.g., sentence-transformers).
    """

    def __init__(self) -> None:
        # Pre-fit vectorizer on a small representative corpus.
        # PROTOTYPE: In production, this would be pre-trained offline.
        sample_docs = [
            "rotate credentials password tokens secrets",
            "network reroute traffic firewall block ip address",
            "read file data asset exfiltrate download upload",
            "process spawn execute command scripting interpreter",
            "login authentication credential use assume role",
            "registry key write persistence autostart",
            "isolate host quarantine endpoint network block",
            "deploy honeypot honeycred deception credential",
        ]
        self._vectorizer = TfidfVectorizer(min_df=1, stop_words='english', ngram_range=(1, 2))
        self._vectorizer.fit(sample_docs)

    def score(
        self,
        declared_scope: str,
        actual_action: str,
    ) -> Tuple[float, float, str]:
        """
        Returns (drift_score, confidence, explanation).

        drift_score: float in [0, 1], where 0 = no drift, 1 = complete divergence.
        """
        if not declared_scope or not actual_action:
            return 0.0, 0.0, "empty input"

        try:
            vecs = self._vectorizer.transform([declared_scope, actual_action])
            sim = float(cosine_similarity(vecs[0], vecs[1])[0, 0])
            drift = 1.0 - sim
            confidence = 0.55  # PROTOTYPE: fixed calibration

            if drift < 0.2:
                explanation = "Low drift: action closely matches declared scope."
            elif drift < 0.5:
                explanation = f"Moderate drift ({drift:.2f}): action partially diverges from declared scope."
            else:
                explanation = f"HIGH drift ({drift:.2f}): action significantly diverges from declared scope. Review recommended."

            return float(drift), confidence, explanation

        except Exception as exc:
            return 0.0, 0.0, f"scoring error: {exc}"
