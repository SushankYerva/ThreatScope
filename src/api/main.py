from fastapi import FastAPI, Depends, Query
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Tuple, Optional
import time

from src.models.predict import ThreatClassifier
from src.utils.alert_logger import AlertLogger


class FeatureVectorIn(BaseModel):
    """
    Flexible feature input.
    We keep known fields explicit for docs,
    but allow unknown numeric fields so we can evolve features.
    """
    flow_duration_ms: Optional[float] = Field(None, ge=0)
    pkt_rate: Optional[float] = Field(None, ge=0)
    avg_pkt_size: Optional[float] = Field(None, ge=0)
    std_pkt_size: Optional[float] = Field(None, ge=0)
    bytes_total: Optional[float] = Field(None, ge=0)
    syn_count: Optional[float] = Field(None, ge=0)
    fin_count: Optional[float] = Field(None, ge=0)
    psh_count: Optional[float] = Field(None, ge=0)
    entropy_dst_port: Optional[float] = Field(None, ge=0)

    class Config:
        extra = "allow"  # accept future features


class PredictionOut(BaseModel):
    label: str
    score: float


class AlertOut(BaseModel):
    timestamp: float
    flow_key: Dict[str, Any]
    prediction: PredictionOut


def _flow_key_tuple_to_dict(flow_key: Tuple[str, str, int, int, str]) -> Dict[str, Any]:
    """
    Represent internal FlowKey tuple in a structured way for API responses.
    FlowKey = (src_ip, dst_ip, src_port, dst_port, protocol)
    """
    return {
        "src_ip": flow_key[0],
        "dst_ip": flow_key[1],
        "src_port": flow_key[2],
        "dst_port": flow_key[3],
        "protocol": flow_key[4],
    }


def create_app(
    classifier: ThreatClassifier,
    logger: AlertLogger,
) -> FastAPI:
    """
    Dependency injection entry point.
    Tests can build an app with fake classifier and fake logger.
    Runtime can build with real model + sqlite.
    """
    app = FastAPI(title="ThreatScope API", version="0.1.0")

    def get_classifier():
        return classifier

    def get_logger():
        return logger

    @app.post("/predict", response_model=PredictionOut)
    def predict_endpoint(
        body: FeatureVectorIn,
        clf: ThreatClassifier = Depends(get_classifier),
    ):
        """
        Input: FeatureVectorIn (single aggregated flow's features)
        Output: label + score
        """
        features_dict = body.dict()
        pred = clf.predict_flow(features_dict)
        return PredictionOut(label=pred["label"], score=pred["score"])

    @app.get("/alerts", response_model=List[AlertOut])
    def alerts_endpoint(
        limit: int = Query(50, ge=1, le=200),
        log: AlertLogger = Depends(get_logger),
    ):
        """
        Return most recent alerts from SQLite
        """
        rows = log.get_recent_alerts(limit=limit)
        out: List[AlertOut] = []
        for row in rows:
            out.append(
                AlertOut(
                    timestamp=row["timestamp"],
                    flow_key=_flow_key_tuple_to_dict(tuple(row["flow_key"])),
                    prediction=PredictionOut(
                        label=row["prediction"]["label"],
                        score=row["prediction"]["score"],
                    ),
                )
            )
        return out

    return app


# optional runtime bootstrapping
# This lets you run:
#   python -m src.api.main
# Assumes you have a trained model at ./model_artifacts/model.joblib
# and feature_order.json in same folder.
if __name__ == "__main__":
    import uvicorn
    import os
    from pathlib import Path

    # resolve paths
    artifacts_dir = Path(os.getenv("THREATSCOPE_ARTIFACTS", "model_artifacts"))
    model_path = artifacts_dir / "model.joblib"
    order_path = artifacts_dir / "feature_order.json"

    clf = ThreatClassifier(
        model_path=str(model_path),
        feature_order_path=str(order_path),
    )
    log = AlertLogger(db_path=os.getenv("THREATSCOPE_DB", "threatscope_alerts.db"))

    app_instance = create_app(clf, log)

    uvicorn.run(app_instance, host="0.0.0.0", port=8000)
