from typing import Dict, Tuple, List, Any
import time
import statistics
import math


FlowKey = Tuple[str, str, int, int, str]  # (src_ip, dst_ip, src_port, dst_port, protocol)


class FlowFeatureExtractor:
    """
    Tracks flows and builds feature vectors.

    Policy
    - A flow is identified by (src_ip, dst_ip, src_port, dst_port, protocol)
    - We collect packets over a time window
    - When window closes or flow goes idle we emit a FeatureVector dict
    """

    def __init__(self, window_ms: int = 2000, max_idle_ms: int = 5000):
        self.window_ms = window_ms
        self.max_idle_ms = max_idle_ms

        # flow_state maps FlowKey -> internal stats
        self.flow_state: Dict[FlowKey, Dict[str, Any]] = {}

    def ingest_packet(
        self, packet: Dict[str, Any]
    ) -> List[Tuple[FlowKey, Dict[str, Any]]]:
        """
        packet: PacketRecord dict
        returns: list of (flow_key, feature_vector) for flows ready to classify
        Most calls will return []
        """
        now_ms = int(packet["timestamp"] * 1000)

        key: FlowKey = (
            packet["src_ip"],
            packet["dst_ip"],
            packet.get("src_port") or -1,
            packet.get("dst_port") or -1,
            packet["protocol"],
        )

        st = self.flow_state.get(key)
        if st is None:
            st = {
                "first_ts": now_ms,
                "last_ts": now_ms,
                "pkt_sizes": [packet["pkt_len"]],
                "total_bytes": packet["pkt_len"],
                "syn": int(packet["tcp_flags"]["SYN"]) if packet["tcp_flags"] else 0,
                "fin": int(packet["tcp_flags"]["FIN"]) if packet["tcp_flags"] else 0,
                "psh": int(packet["tcp_flags"]["PSH"]) if packet["tcp_flags"] else 0,
                "dst_ports": [packet.get("dst_port") or -1],
            }
            self.flow_state[key] = st
        else:
            st["last_ts"] = now_ms
            st["pkt_sizes"].append(packet["pkt_len"])
            st["total_bytes"] += packet["pkt_len"]
            st["dst_ports"].append(packet.get("dst_port") or -1)
            if packet["tcp_flags"]:
                st["syn"] += int(packet["tcp_flags"]["SYN"])
                st["fin"] += int(packet["tcp_flags"]["FIN"])
                st["psh"] += int(packet["tcp_flags"]["PSH"])

        emit_list: List[Tuple[FlowKey, Dict[str, Any]]] = []

        flow_age_ms = st["last_ts"] - st["first_ts"]
        idle_ms = now_ms - st["last_ts"]

        window_expired = flow_age_ms >= self.window_ms
        idle_expired = idle_ms >= self.max_idle_ms

        if window_expired or idle_expired:
            feat = self._build_feature_vector(st)
            emit_list.append((key, feat))
            # reset state for this flow
            self.flow_state.pop(key, None)

        return emit_list

    def force_flush(self) -> List[Tuple[FlowKey, Dict[str, Any]]]:
        """
        Emit all remaining flows on shutdown.
        """
        out: List[Tuple[FlowKey, Dict[str, Any]]] = []
        for key, st in list(self.flow_state.items()):
            feat = self._build_feature_vector(st)
            out.append((key, feat))
            self.flow_state.pop(key, None)
        return out

    def _build_feature_vector(self, st: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert internal flow stats into model features.
        """
        duration_ms = max(st["last_ts"] - st["first_ts"], 1)
        pkt_sizes = st["pkt_sizes"]
        pkt_rate = len(pkt_sizes) / (duration_ms / 1000.0)

        avg_pkt = statistics.fmean(pkt_sizes)
        std_pkt = statistics.pstdev(pkt_sizes) if len(pkt_sizes) > 1 else 0.0
        ent_port = self._entropy(st["dst_ports"])

        return {
            "flow_duration_ms": float(duration_ms),
            "pkt_rate": float(pkt_rate),
            "avg_pkt_size": float(avg_pkt),
            "std_pkt_size": float(std_pkt),
            "bytes_total": int(st["total_bytes"]),
            "syn_count": int(st["syn"]),
            "fin_count": int(st["fin"]),
            "psh_count": int(st["psh"]),
            "entropy_dst_port": float(ent_port),
        }

    def _entropy(self, values: List[int]) -> float:
        """
        Shannon entropy over list of integers.
        """
        if not values:
            return 0.0
        counts: Dict[int, int] = {}
        for v in values:
            counts[v] = counts.get(v, 0) + 1
        total = float(len(values))
        ent = 0.0
        for c in counts.values():
            p = c / total
            ent -= p * math.log2(p)
        return ent
