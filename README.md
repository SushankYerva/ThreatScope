# ThreatScope

Intrusion detection pipeline.

Captures packets. Builds per-flow features. Classifies using a trained ML model. Logs high risk flows. Exposes a FastAPI service.

## Modules

1. `PacketSniffer`  
   Live or offline capture. Normalizes packets into `PacketRecord`.

2. `FlowFeatureExtractor`  
   Maintains rolling state per flow and emits `FeatureVector` dicts.

3. `ThreatClassifier`  
   Loads trained model (`model_artifacts/model.joblib`) and feature order.  
   Returns `{label, score}`.

4. `AlertLogger`  
   SQLite backed alert store. Persists high risk predictions.

5. `RealTimeMonitor`  
   Orchestrates sniffer → extractor → classifier → logger. Used for live monitoring.

6. `FastAPI` service (`src/api/main.py`)  
   - `POST /predict`  
     Input: flow feature vector  
     Output: `{"label": "...", "score": 0.xx}`  
   - `GET /alerts?limit=50`  
     Output: recent alerts from SQLite.

## Run locally

```bash
pip install -r requirements.txt
export THREATSCOPE_ARTIFACTS=./model_artifacts
export THREATSCOPE_DB=./threatscope_alerts.db
python -m src.api.main
