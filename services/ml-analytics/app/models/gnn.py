"""
GNN model stub for Kaaladrishti.

Provides GNN-based node embedding and anomaly scoring using PyTorch Geometric.

PROTOTYPE NOTE: This uses randomly initialized weights. The interface contract
is real and typed; only the model weights are stubs. A real deployment would
load pre-trained weights from a checkpoint file.

Training: see services/ml-analytics/training/ for the offline dataset loaders
(UNSW-NB15, CSE-CIC-IDS2018). Training is NOT on the live inference path.
"""
from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from typing import Dict, List, Tuple

import numpy as np
import torch
import torch.nn.functional as F
from torch import nn

# PyTorch Geometric is imported here. If torch-geometric is not installed,
# we fall back to a pure numpy stub that produces the same interface.
try:
    from torch_geometric.nn import GCNConv
    HAS_TORCH_GEOMETRIC = True
except ImportError:
    HAS_TORCH_GEOMETRIC = False


# ---------------------------------------------------------------------------
# Model architecture
# ---------------------------------------------------------------------------

class GCNEncoder(nn.Module):
    """
    Two-layer Graph Convolutional Network encoder.

    Produces 64-dimensional node embeddings from 32-dimensional input features.

    PROTOTYPE NOTE: Input features are computed heuristically from node
    properties (not trained on real data). A production model would use
    pre-trained node2vec or supervised feature extraction.
    """

    def __init__(self, in_channels: int = 32, hidden_channels: int = 64, out_channels: int = 32):
        super().__init__()
        if HAS_TORCH_GEOMETRIC:
            self.conv1 = GCNConv(in_channels, hidden_channels)
            self.conv2 = GCNConv(hidden_channels, out_channels)
        else:
            # Fallback: simple linear layers (no message passing).
            self.conv1 = nn.Linear(in_channels, hidden_channels)
            self.conv2 = nn.Linear(hidden_channels, out_channels)

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        if HAS_TORCH_GEOMETRIC:
            x = F.relu(self.conv1(x, edge_index))
            x = self.conv2(x, edge_index)
        else:
            x = F.relu(self.conv1(x))
            x = self.conv2(x)
        return x


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

# Node type → integer ID for one-hot feature encoding.
NODE_TYPE_MAP = {
    0: 0,  # UNSPECIFIED
    1: 1,  # PRINCIPAL
    2: 2,  # CREDENTIAL
    3: 3,  # HOST
    4: 4,  # PROCESS
    5: 5,  # MODULE
    6: 6,  # NETWORK_SOCKET
    7: 7,  # DATA_ASSET
    8: 8,  # REGISTRY_KEY
}
NUM_NODE_TYPES = 9


def node_to_features(node) -> np.ndarray:
    """
    Extract a 32-dimensional feature vector from a GraphNode proto.

    Features (indices):
      0-8:   one-hot node type encoding
      9:     confidence [0,1]
      10:    recency_decay [0,1]
      11:    is_crown_jewel (from properties)
      12-31: padding zeros (reserved for future features)

    PROTOTYPE NOTE: This is a heuristic feature extractor.
    """
    feat = np.zeros(32, dtype=np.float32)

    node_type = int(getattr(node, 'node_type', 0))
    if node_type < NUM_NODE_TYPES:
        feat[node_type] = 1.0

    feat[9]  = float(getattr(node, 'confidence', 0.0))
    feat[10] = float(getattr(node, 'recency_decay', 1.0))

    props = dict(getattr(node, 'properties', {}))
    feat[11] = 1.0 if props.get('asset.sensitivity') == 'crown_jewel' else 0.0

    return feat


# ---------------------------------------------------------------------------
# GNNModel — the exported interface
# ---------------------------------------------------------------------------

class GNNModel:
    """
    GNN-based anomaly/risk scorer.

    Interface (called by grpc_server.py):
        score(subject_node_id, nodes, edges) -> (anomaly_score, confidence, embeddings)

    Returns:
        anomaly_score: float in [0, 1] — higher = more anomalous
        confidence:    float in [0, 1] — model confidence in the score
        embeddings:    dict[node_id -> bytes] — 32-float embedding (little-endian)
    """

    version = "gnn-gcn-stub-v1"

    def __init__(self) -> None:
        torch.manual_seed(42)  # Reproducible stub outputs.
        self.model = GCNEncoder(in_channels=32, hidden_channels=64, out_channels=32)
        self.model.eval()

    def score(
        self,
        subject_node_id: str,
        nodes: list,
        edges: list,
    ) -> Tuple[float, float, Dict[str, bytes]]:
        if not nodes:
            return 0.0, 0.0, {}

        # Build node index.
        node_ids = [getattr(n, 'node_id', str(i)) for i, n in enumerate(nodes)]
        node_idx = {nid: i for i, nid in enumerate(node_ids)}

        # Build feature matrix.
        feats = np.stack([node_to_features(n) for n in nodes], axis=0)
        x = torch.tensor(feats, dtype=torch.float32)

        # Build edge index.
        src_list, dst_list = [], []
        for e in edges:
            src = node_idx.get(getattr(e, 'src_node_id', ''))
            dst = node_idx.get(getattr(e, 'dst_node_id', ''))
            if src is not None and dst is not None:
                src_list.append(src)
                dst_list.append(dst)

        if src_list:
            edge_index = torch.tensor([src_list, dst_list], dtype=torch.long)
        else:
            edge_index = torch.zeros((2, 0), dtype=torch.long)

        # Forward pass.
        with torch.no_grad():
            embeddings = self.model(x, edge_index)

        # Anomaly score: cosine distance of subject node embedding from the
        # centroid (the mean embedding represents "normal").
        # PROTOTYPE NOTE: real anomaly detection would compare against a
        # trained normal-behavior centroid, not the batch centroid.
        centroid = embeddings.mean(dim=0, keepdim=True)
        subject_idx = node_idx.get(subject_node_id, 0)
        subject_emb = embeddings[subject_idx].unsqueeze(0)
        cosine_sim = F.cosine_similarity(subject_emb, centroid).item()
        # Convert to [0,1] anomaly score (higher sim = less anomalous).
        anomaly_score = float(max(0.0, min(1.0, (1.0 - cosine_sim) / 2.0)))

        # Heuristic boost for crown-jewel access or suspicious connections.
        for n in nodes:
            props = dict(getattr(n, 'properties', {}))
            if props.get('asset.sensitivity') == 'crown_jewel':
                anomaly_score = min(1.0, anomaly_score * 1.5 + 0.2)
            if props.get('socket.dst_port') == '4444':
                anomaly_score = min(1.0, anomaly_score * 1.4 + 0.15)

        confidence = 0.6  # PROTOTYPE: fixed confidence without calibration

        # Pack embeddings as bytes.
        emb_dict: Dict[str, bytes] = {}
        for i, nid in enumerate(node_ids):
            emb_dict[nid] = embeddings[i].numpy().astype(np.float32).tobytes()

        return anomaly_score, confidence, emb_dict
