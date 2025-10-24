# ThreatScope  
[![Build Status](https://github.com/<your-username>/threatscope/actions/workflows/ci.yml/badge.svg)](https://github.com/<your-username>/threatscope/actions)
[![Python Version](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Made with Scapy](https://img.shields.io/badge/Made%20with-Scapy-orange.svg)](https://scapy.net/)
[![XGBoost](https://img.shields.io/badge/ML-XGBoost-yellow.svg)](https://xgboost.ai/)

---

### ⚙️ Overview

**ThreatScope** is an **intermediate-to-advanced cybersecurity and machine-learning project** that performs **real-time network intrusion detection**.

It captures packets, computes flow-level statistics, applies a trained ML classifier (Random Forest or XGBoost), and logs malicious traffic through a REST API or SQLite database.

---

### 🧩 Architecture

```
 ┌──────────────┐   packets   ┌────────────┐   features   ┌─────────────┐   predictions   ┌────────────┐
 │ Network Intf │ ─────────▶ │ Sniffer    │ ───────────▶ │ Feature Ext │ ─────────────▶ │ ML Model   │
 └──────────────┘             └────────────┘               └─────────────┘                 └────────────┘
                                                                                 ↓
                                                                            ┌────────────┐
                                                                            │ Alert Log  │
                                                                            └────────────┘
                                                                                 ↓
                                                                            ┌────────────┐
                                                                            │ FastAPI    │
                                                                            └────────────┘
```

---

### 🧠 Features

| Capability | Description |
|-------------|-------------|
| **Live capture** | Uses Scapy to sniff TCP/UDP packets from an interface. |
| **Offline analysis** | Reads `.pcap` or `.pcapng` files with PyShark. |
| **Feature extraction** | Calculates packet rate, entropy, byte totals, and TCP flag counts. |
| **ML classifier** | Trains and serves XGBoost / RandomForest models. |
| **SQLite logging** | Stores alerts in local database with timestamps. |
| **REST API** | FastAPI endpoints `/predict` and `/alerts`. |
| **Docker & CI** | Ready to containerize and test on GitHub Actions. |

---

### 🏗️ Project Layout

```
threatscope/
├── src/
│   ├── capture/           # packet collection
│   ├── features/          # flow feature builder
│   ├── models/            # ML training and inference
│   ├── utils/             # alert logger (SQLite)
│   ├── controller/        # orchestrator
│   └── api/               # FastAPI service
├── datasets/              # optional: training CSVs
├── model_artifacts/       # saved model.joblib + feature_order.json
├── tests/                 # pytest unit tests
├── requirements.txt
├── Dockerfile
├── LICENSE
└── README.md
```

---

### 🚀 Quick Start

#### 1. Clone and install
```bash
git clone https://github.com/<your-username>/threatscope.git
cd threatscope
pip install -r requirements.txt
```

#### 2. Train a model
Prepare a labeled CSV from CICIDS2017 or UNSW-NB15:

```bash
python -m src.models.train   --data ./datasets/flows_labeled.csv   --label label   --model xgboost   --out ./model_artifacts
```

Output files:
```
model_artifacts/
├── model.joblib
├── feature_order.json
└── metrics.json
```

#### 3. Run API service
```bash
export THREATSCOPE_ARTIFACTS=./model_artifacts
export THREATSCOPE_DB=./threatscope_alerts.db
python -m src.api.main
```
Visit **http://localhost:8000/docs** for Swagger UI.

#### 4. Analyze a PCAP file (offline mode)
```python
from src.controller.realtime_monitor import RealTimeMonitor
from src.models.predict import ThreatClassifier
from src.utils.alert_logger import AlertLogger

clf = ThreatClassifier("model_artifacts/model.joblib", "model_artifacts/feature_order.json")
logger = AlertLogger("threatscope_alerts.db")

monitor = RealTimeMonitor(
    classifier=clf,
    logger=logger,
    pcap_file="samples/test_traffic.pcap"
)

alerts = monitor.run_once(max_packets=5000)
print(f"Generated {len(alerts)} alerts")
```

#### 5. Docker
```bash
docker build -t threatscope .
docker run --network host -v $(pwd)/model_artifacts:/app/model_artifacts threatscope
```

---

### 🧪 Testing and CI

```bash
pytest -q
```

GitHub Actions automatically runs `pytest` for every push and pull request.

---

### 📊 Example Metrics Output
From `model_artifacts/metrics.json`:
```json
{
  "precision_macro": 0.92,
  "recall_macro": 0.90,
  "f1_macro": 0.91,
  "roc_auc_macro": 0.95
}
```

---

### ⚖️ Legal / Ethical Use

ThreatScope is intended **only for defensive network monitoring** within systems you control or have written authorization to test.  
Do **not** use it to capture third-party traffic or for offensive activities.  
The code performs **passive packet inspection**, not exploitation or active scanning.

---

### 🧾 License

This project is released under the [MIT License](LICENSE).

---

### 🤝 Contributing

Pull requests are welcome.  
See [CONTRIBUTING.md](CONTRIBUTING.md) for coding style, branching model, and review process.

---

### 🧑‍💻 Maintainer

**Author:** [Your Name](https://github.com/<your-username>)  
**LinkedIn:** [linkedin.com/in/maharshi007](https://www.linkedin.com/in/maharshi007/)

---

### 🌐 References

- CICIDS2017 Dataset — *Canadian Institute for Cybersecurity*  
- UNSW-NB15 Dataset — *Australian Centre for Cyber Security*  
- Scapy Docs — https://scapy.readthedocs.io  
- PyShark Docs — https://github.com/KimiNewt/pyshark  

---
