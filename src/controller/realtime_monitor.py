from typing import List, Dict, Any, Optional
import time

from src.capture.sniffer import PacketSniffer
from src.features.extractor import FlowFeatureExtractor, FlowKey
from src.models.predict import ThreatClassifier
from src.utils.alert_logger import AlertLogger


class RealTimeMonitor:
    """
    Connects sniffer, feature extractor, classifier, and logger.

    run_once pulls a finite batch of packets.
    It classifies flows that are ready and logs malicious events.
    """

    def __init__(
        self,
        classifier: ThreatClassifier,
        logger: AlertLogger,
        iface: Optional[str] = None,
        pcap_file: Optional[str] = None,
        capture_filter: str = "tcp or udp",
        window_ms: int = 2000,
        score_threshold: float = 0.8,
    ):
        """
        iface: live interface for sniffing (root usually required)
        pcap_file: offline analysis path
        capture_filter: BPF/Wireshark style filter to reduce noise
        """
        self.sniffer = PacketSniffer(
            iface=iface,
            pcap_file=pcap_file,
            capture_filter=capture_filter,
        )
        self.extractor = FlowFeatureExtractor(window_ms=window_ms)
        self.classifier = classifier
        self.logger = logger
        self.score_threshold = score_threshold

    def run_once(self, max_packets: int = 1000) -> List[Dict[str, Any]]:
        """
        Pull up to max_packets packets from sniffer.start_stream()

        Return list of alert dicts for this cycle.
        A "cycle" is one bounded call to run_once.
        """
        alerts_out: List[Dict[str, Any]] = []
        pkt_iter = self.sniffer.start_stream()

        for i, pkt in enumerate(pkt_iter):
            ready_flows = self.extractor.ingest_packet(pkt)

            for flow_key, feat in ready_flows:
                pred = self.classifier.predict_flow(feat)

                if pred["score"] >= self.score_threshold and pred["label"] != "benign":
                    ts = time.time()
                    alert_entry = {
                        "ts": ts,
                        "flow_key": flow_key,
                        "prediction": pred,
                    }
                    alerts_out.append(alert_entry)
                    self.logger.record_alert(flow_key, pred, ts)

            if i + 1 >= max_packets:
                # stop the sniffer cleanly
                self.sniffer.stop()
                break

        # flush remainder and classify them too
        remaining = self.extractor.force_flush()
        for flow_key, feat in remaining:
            pred = self.classifier.predict_flow(feat)
            if pred["score"] >= self.score_threshold and pred["label"] != "benign":
                ts = time.time()
                alert_entry = {
                    "ts": ts,
                    "flow_key": flow_key,
                    "prediction": pred,
                }
                alerts_out.append(alert_entry)
                self.logger.record_alert(flow_key, pred, ts)

        return alerts_out
