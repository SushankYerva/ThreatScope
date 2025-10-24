import time
from fastapi.testclient import TestClient

from src.api.main import create_app, PredictionOut, AlertOut


class DummyClassifier:
    def predict_flow(self, features):
        # deterministic fake logic for tests
        return {
            "label": "malicious" if features.get("bytes_total", 0) > 1000 else "benign",
            "score": 0.91,
        }


class DummyLogger:
    def get_recent_alerts(self, limit=50):
        now = time.time()
        return [
            {
                "timestamp": now,
                "flow_key": ("10.0.0.5", "10.0.0.10", 443, 51542, "TCP"),
                "prediction": {"label": "dos", "score": 0.97},
            }
        ]


def build_test_client():
    clf = DummyClassifier()
    log = DummyLogger()
    app = create_app(clf, log)
    return TestClient(app)


def test_predict_endpoint_structure():
    client = build_test_client()
    payload = {
        "flow_duration_ms": 250.0,
        "bytes_total": 2048,
        "pkt_rate": 10.0,
    }
    resp = client.post("/predict", json=payload)
    assert resp.status_code == 200
    body = resp.json()

    # contract check
    assert "label" in body
    assert "score" in body
    assert isinstance(body["label"], str)
    assert isinstance(body["score"], float)


def test_alerts_endpoint_structure():
    client = build_test_client()
    resp = client.get("/alerts?limit=5")
    assert resp.status_code == 200

    arr = resp.json()
    assert isinstance(arr, list)
    assert len(arr) == 1

    item = arr[0]
    assert "timestamp" in item
    assert "flow_key" in item
    assert "prediction" in item

    fk = item["flow_key"]
    assert set(fk.keys()) == {
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
    }

    pred = item["prediction"]
    assert "label" in pred and "score" in pred
