"""
ml_analytics gRPC server — implements MLAnalyticsService from platform.proto.

All five RPCs are implemented:
  - ScoreRisk:           GNN-based anomaly/risk scoring (stub weights)
  - ComputeBlastRadius:  PPR/RWR blast-radius scoring (NetworkX PPR)
  - ForecastNextAttack:  Transformer/LSTM next-technique forecast (stub)
  - ScoreIntentLineage:  cosine-distance drift scoring (sklearn TF-IDF)
  - EvaluateDrift:       CUSUM change-point detection (scikit-learn)

ARCHITECTURE NOTE: Python is always the callee. It never calls back to Go.
All decisions remain in Go. This service returns advisory analysis only.
"""
from __future__ import annotations

import logging
import os
from concurrent import futures

import grpc

# Generated gRPC stubs (from scripts/gen_proto.py)
from generated.python import platform_pb2 as pb
from generated.python import platform_pb2_grpc as pb_grpc

from app.models.gnn import GNNModel
from app.models.blast_radius import BlastRadiusScorer
from app.models.next_attack import NextAttackForecaster
from app.models.intent_lineage import IntentLineageScorer
from app.models.drift_detection import DriftDetector

logger = logging.getLogger("ml_analytics")


class MLAnalyticsServicer(pb_grpc.MLAnalyticsServiceServicer):
    """
    Implements all five MLAnalyticsService RPCs.

    Models are loaded once at startup and shared across requests.
    No global mutable state is modified during request handling.
    """

    def __init__(self) -> None:
        logger.info("Loading ML models...")
        self.gnn = GNNModel()
        self.blast_radius = BlastRadiusScorer()
        self.next_attack = NextAttackForecaster()
        self.intent_lineage = IntentLineageScorer()
        self.drift_detector = DriftDetector()
        logger.info("All models loaded.")

    def ScoreRisk(
        self, request: pb.RiskScoreRequest, context: grpc.ServicerContext
    ) -> pb.RiskScoreResponse:
        """GNN-based anomaly/risk score for a subgraph."""
        logger.debug("ScoreRisk: request_id=%s", request.request_id)
        try:
            score, confidence, embeddings = self.gnn.score(
                subject_node_id=request.subject_node_id,
                nodes=list(request.nodes),
                edges=list(request.edges),
            )
            return pb.RiskScoreResponse(
                request_id=request.request_id,
                anomaly_score=float(score),
                confidence=float(confidence),
                node_embeddings={k: v for k, v in embeddings.items()},
                model_version=self.gnn.version,
            )
        except Exception as exc:
            logger.error("ScoreRisk error: %s", exc, exc_info=True)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"ScoreRisk error: {exc}")
            return pb.RiskScoreResponse()

    def ComputeBlastRadius(
        self, request: pb.RiskScoreRequest, context: grpc.ServicerContext
    ) -> pb.BlastRadius:
        """PPR/RWR blast-radius scoring."""
        logger.debug("ComputeBlastRadius: request_id=%s", request.request_id)
        try:
            result = self.blast_radius.compute(
                subject_node_id=request.subject_node_id,
                nodes=list(request.nodes),
                edges=list(request.edges),
            )
            return pb.BlastRadius(
                subject_node_id=request.subject_node_id,
                crown_jewel_scores=result.crown_jewel_scores,
                propagation_path=result.propagation_path,
                overall_blast_score=float(result.overall_score),
                confidence=float(result.confidence),
            )
        except Exception as exc:
            logger.error("ComputeBlastRadius error: %s", exc, exc_info=True)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(exc))
            return pb.BlastRadius()

    def ForecastNextAttack(
        self, request: pb.NextAttackForecastRequest, context: grpc.ServicerContext
    ) -> pb.NextAttackForecastResponse:
        """Transformer/LSTM next-technique forecast."""
        logger.debug("ForecastNextAttack: request_id=%s", request.request_id)
        try:
            predictions = self.next_attack.forecast(
                observed_techniques=list(request.observed_techniques),
                top_k=request.top_k or 3,
            )
            return pb.NextAttackForecastResponse(
                request_id=request.request_id,
                predictions=[
                    pb.TechniquePrediction(
                        technique_id=p.technique_id,
                        technique_name=p.technique_name,
                        probability=float(p.probability),
                    )
                    for p in predictions
                ],
                model_version=self.next_attack.version,
            )
        except Exception as exc:
            logger.error("ForecastNextAttack error: %s", exc, exc_info=True)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(exc))
            return pb.NextAttackForecastResponse()

    def ScoreIntentLineage(
        self, request: pb.IntentLineageRequest, context: grpc.ServicerContext
    ) -> pb.IntentLineageResponse:
        """
        Cosine-distance drift between declared scope and actual action.

        This is Kaaladrishti's in-scope intent lineage tracker — NOT Pillar 5.
        It returns a drift score and explanation. It NEVER makes execution decisions.
        """
        logger.debug("ScoreIntentLineage: request_id=%s workflow_id=%s",
                     request.request_id, request.workflow_id)
        try:
            score, confidence, explanation = self.intent_lineage.score(
                declared_scope=request.declared_scope_text,
                actual_action=request.actual_action_text,
            )
            return pb.IntentLineageResponse(
                request_id=request.request_id,
                drift_score=float(score),
                confidence=float(confidence),
                explanation=explanation,
            )
        except Exception as exc:
            logger.error("ScoreIntentLineage error: %s", exc, exc_info=True)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(exc))
            return pb.IntentLineageResponse()

    def EvaluateDrift(
        self, request: pb.DriftEvaluationRequest, context: grpc.ServicerContext
    ) -> pb.DriftEvaluationResponse:
        """CUSUM/ADWIN baseline change-point detection."""
        logger.debug("EvaluateDrift: request_id=%s metric=%s",
                     request.request_id, request.metric_name)
        try:
            result = self.drift_detector.evaluate(
                values=list(request.recent_values),
                baseline_mean=request.baseline_mean,
                baseline_stddev=request.baseline_stddev,
            )
            return pb.DriftEvaluationResponse(
                request_id=request.request_id,
                drift_detected=result.drift_detected,
                drift_magnitude=float(result.magnitude),
                confidence=float(result.confidence),
                change_point_idx=result.change_point_idx,
                detector_type=result.detector_type,
                model_version="cusum-adwin-v1",
            )
        except Exception as exc:
            logger.error("EvaluateDrift error: %s", exc, exc_info=True)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(exc))
            return pb.DriftEvaluationResponse()


def serve(port: int = 50051, max_workers: int = 4) -> None:
    """Start the gRPC server."""
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=max_workers))
    pb_grpc.add_MLAnalyticsServiceServicer_to_server(MLAnalyticsServicer(), server)

    addr = f"[::]:{port}"
    server.add_insecure_port(addr)
    server.start()
    logger.info("ML analytics gRPC server listening on %s", addr)

    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        logger.info("Shutting down ML analytics server")
        server.stop(grace=5)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG if os.getenv("DEBUG") else logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    port = int(os.getenv("KAALADRISHTI_ML_GRPC_PORT", "50051"))
    serve(port=port)
