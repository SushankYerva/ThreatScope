from src.controller.realtime_monitor import RealTimeMonitor
from src.models.predict import ThreatClassifier
from src.utils.alert_logger import AlertLogger

# paths to model artifacts
clf = ThreatClassifier(
    "model_artifacts/model.joblib",
    "model_artifacts/feature_order.json"
)

# sqlite db file for alerts
logger = AlertLogger("threatscope_alerts.db")

# analyze offline pcap
monitor = RealTimeMonitor(
    classifier=clf,
    logger=logger,
    pcap_file="samples/test_traffic.pcap",  # change if different path
    capture_filter="tcp or udp"
)

alerts = monitor.run_once(max_packets=5000)

print("Analysis complete.")
print("Number of suspicious alerts:", len(alerts))
for a in alerts:
    print(a)
