from src.controller.realtime_monitor import RealTimeMonitor
from src.models.predict import ThreatClassifier
from src.utils.alert_logger import AlertLogger

clf = ThreatClassifier(
    "model_artifacts/model.joblib",
    "model_artifacts/feature_order.json"
)

logger = AlertLogger("threatscope_alerts.db")

monitor = RealTimeMonitor(
    classifier=clf,
    logger=logger,
    iface="eth0",              # change this to your real interface, e.g. "wlan0" or "Wi-Fi"
    capture_filter="tcp or udp"
)

alerts = monitor.run_once(max_packets=2000)

print("Live capture complete.")
print("Suspicious alerts:", len(alerts))
for a in alerts:
    print(a)
