"""
Blast radius scorer using Personalized PageRank / Random-Walk-with-Restart.

Computes the probabilistic reach of an anomalous subject node to crown-jewel
DataAsset nodes in the enterprise graph, weighted by edge confidence.

Algorithm:
  1. Build a directed weighted graph from nodes/edges (weight = confidence).
  2. Run NetworkX personalized_pagerank() with the subject node as the
     personalization source (alpha=0.85, the standard PPR damping factor).
  3. Extract scores for nodes with asset.sensitivity == "crown_jewel".
  4. Overall blast score = max crown jewel score (worst-case reachability).

References:
  - Page et al. (1999) "The PageRank Citation Ranking: Bringing Order to the Web"
  - Faloutsos et al. (2004) "Fast discovery of connection subgraphs" (RWR)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

import networkx as nx


@dataclass
class BlastRadiusResult:
    crown_jewel_scores: Dict[str, float] = field(default_factory=dict)
    propagation_path: List[str] = field(default_factory=list)
    overall_score: float = 0.0
    confidence: float = 0.0


class BlastRadiusScorer:
    """
    Computes probabilistic blast radius via Personalized PageRank.

    Crown jewel nodes are DataAsset nodes with property asset.sensitivity == crown_jewel.
    The PPR score of each crown jewel relative to the subject node is the reachability score.
    """

    def compute(
        self,
        subject_node_id: str,
        nodes: list,
        edges: list,
    ) -> BlastRadiusResult:
        if not nodes:
            return BlastRadiusResult()

        # Build directed weighted graph.
        G = nx.DiGraph()
        crown_jewels: set[str] = set()

        for n in nodes:
            node_id = getattr(n, 'node_id', '')
            props = dict(getattr(n, 'properties', {}))
            G.add_node(node_id, node_type=int(getattr(n, 'node_type', 0)))
            if props.get('asset.sensitivity') == 'crown_jewel':
                crown_jewels.add(node_id)

        for e in edges:
            src = getattr(e, 'src_node_id', '')
            dst = getattr(e, 'dst_node_id', '')
            weight = float(getattr(e, 'confidence', 0.5))
            if G.has_node(src) and G.has_node(dst):
                # Use confidence as edge weight (higher = more traversable).
                G.add_edge(src, dst, weight=weight)

        if subject_node_id not in G:
            return BlastRadiusResult()

        if len(G.nodes) == 0:
            return BlastRadiusResult()

        # Personalized PageRank: personalization vector = 1 on subject node.
        personalization = {n: 0.0 for n in G.nodes}
        personalization[subject_node_id] = 1.0

        try:
            ppr_scores = nx.pagerank(
                G,
                alpha=0.85,  # Standard PPR damping factor
                personalization=personalization,
                weight='weight',
                max_iter=200,
                tol=1e-6,
            )
        except nx.PowerIterationFailedConvergence:
            # Fall back to uniform scores if PPR doesn't converge.
            n = len(G.nodes)
            ppr_scores = {node: 1.0 / n for node in G.nodes}

        # Extract crown jewel reachability scores.
        crown_jewel_scores: Dict[str, float] = {}
        for cj_id in crown_jewels:
            if cj_id in ppr_scores:
                crown_jewel_scores[cj_id] = float(ppr_scores[cj_id])

        if not crown_jewel_scores:
            return BlastRadiusResult(confidence=0.5)

        overall_score = max(crown_jewel_scores.values())

        # Compute the most likely propagation path to the highest-risk crown jewel.
        best_cj = max(crown_jewel_scores, key=crown_jewel_scores.get)
        try:
            path = nx.shortest_path(G, source=subject_node_id, target=best_cj, weight=None)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            path = [subject_node_id, best_cj]

        return BlastRadiusResult(
            crown_jewel_scores=crown_jewel_scores,
            propagation_path=path,
            overall_score=float(overall_score),
            confidence=0.65,  # PROTOTYPE: fixed calibration
        )
