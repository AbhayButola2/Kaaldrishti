"""
Next-attack technique forecaster.

PROTOTYPE NOTE: Uses a simple Markov-chain / transition-frequency heuristic
over observed MITRE ATT&CK technique sequences. A production model would use
a trained Transformer or LSTM sequence model.

The interface contract (input/output types) is real and typed.
The model weights are stubs.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List


# MITRE ATT&CK technique transition probabilities (heuristic for prototype).
# Source: rough frequency from public CTI reports.
# TODO(phase-future): Replace with trained Transformer weights.
TRANSITIONS: dict[str, dict[str, float]] = {
    "T1566": {"T1059": 0.35, "T1055": 0.20, "T1071": 0.20, "T1078": 0.15, "T1547": 0.10},  # Phishing → ...
    "T1059": {"T1055": 0.30, "T1071": 0.25, "T1082": 0.20, "T1005": 0.15, "T1547": 0.10},  # Scripting → ...
    "T1055": {"T1071": 0.35, "T1005": 0.30, "T1082": 0.20, "T1083": 0.15},                  # Process injection → ...
    "T1071": {"T1005": 0.40, "T1083": 0.25, "T1560": 0.20, "T1048": 0.15},                  # C2 protocol → ...
    "T1078": {"T1021": 0.35, "T1003": 0.30, "T1087": 0.20, "T1082": 0.15},                  # Valid accounts → ...
    "T1005": {"T1560": 0.40, "T1048": 0.35, "T1071": 0.25},                                  # Local data → ...
    "T1082": {"T1057": 0.30, "T1083": 0.30, "T1135": 0.20, "T1016": 0.20},                  # System info → ...
}

# MITRE ATT&CK technique display names (partial, for prototype).
TECHNIQUE_NAMES: dict[str, str] = {
    "T1566": "Phishing",
    "T1059": "Command and Scripting Interpreter",
    "T1055": "Process Injection",
    "T1071": "Application Layer Protocol",
    "T1078": "Valid Accounts",
    "T1005": "Data from Local System",
    "T1082": "System Information Discovery",
    "T1021": "Remote Services",
    "T1003": "OS Credential Dumping",
    "T1087": "Account Discovery",
    "T1057": "Process Discovery",
    "T1083": "File and Directory Discovery",
    "T1135": "Network Share Discovery",
    "T1016": "System Network Configuration Discovery",
    "T1560": "Archive Collected Data",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1547": "Boot or Logon Autostart Execution",
}


@dataclass
class TechniquePrediction:
    technique_id: str
    technique_name: str
    probability: float


class NextAttackForecaster:
    """
    Predicts the most probable next MITRE ATT&CK technique.

    Uses a Markov-chain heuristic over transition frequencies.
    PROTOTYPE NOTE: Real model would use a trained Transformer/LSTM.
    """

    version = "markov-stub-v1"

    def forecast(
        self,
        observed_techniques: List[str],
        top_k: int = 3,
    ) -> List[TechniquePrediction]:
        if not observed_techniques:
            return self._default_predictions(top_k)

        last_technique = observed_techniques[-1]
        transitions = TRANSITIONS.get(last_technique)

        if not transitions:
            return self._default_predictions(top_k)

        # Sort by probability descending and return top-k.
        sorted_transitions = sorted(transitions.items(), key=lambda x: x[1], reverse=True)
        predictions = []
        for tech_id, prob in sorted_transitions[:top_k]:
            predictions.append(TechniquePrediction(
                technique_id=tech_id,
                technique_name=TECHNIQUE_NAMES.get(tech_id, tech_id),
                probability=prob,
            ))
        return predictions

    def _default_predictions(self, top_k: int) -> List[TechniquePrediction]:
        """Return baseline predictions when no observed technique sequence is available."""
        defaults = [
            ("T1071", 0.25),  # C2 communication is common at mid-stage
            ("T1078", 0.20),  # Valid accounts
            ("T1005", 0.18),  # Data exfil
        ]
        return [
            TechniquePrediction(
                technique_id=tid,
                technique_name=TECHNIQUE_NAMES.get(tid, tid),
                probability=prob,
            )
            for tid, prob in defaults[:top_k]
        ]
