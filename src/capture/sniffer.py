from typing import Generator, Optional, Dict, Any
import time


class PacketSniffer:
    """
    PacketSniffer captures packets from a live interface or from an offline pcap.

    The sniffer returns normalized packet records.
    Each record is a dict with fields:
        timestamp: float
        src_ip: str
        dst_ip: str
        src_port: int | None
        dst_port: int | None
        protocol: str
        pkt_len: int
        tcp_flags: dict | None

    Actual packet parsing will use scapy or pyshark.
    """

    def __init__(
        self,
        iface: Optional[str] = None,
        pcap_file: Optional[str] = None,
        capture_filter: Optional[str] = None,
    ):
        """
        iface: network interface for live capture such as "eth0"
        pcap_file: offline source such as "capture.pcap"
        capture_filter: BPF filter such as "tcp or udp"
        """
        self.iface = iface
        self.pcap_file = pcap_file
        self.capture_filter = capture_filter
        self._running = False

    def start_stream(self) -> Generator[Dict[str, Any], None, None]:
        """
        Yields PacketRecord dicts.
        In final version this will call scapy.sniff or pyshark.LiveCapture.

        For now this is a stub that simulates packets so other modules can run.
        """
        self._running = True

        # placeholder loop
        while self._running:
            fake_packet = {
                "timestamp": time.time(),
                "src_ip": "10.0.0.5",
                "dst_ip": "10.0.0.10",
                "src_port": 443,
                "dst_port": 51542,
                "protocol": "TCP",
                "pkt_len": 512,
                "tcp_flags": {"SYN": 0, "ACK": 1, "FIN": 0, "PSH": 0},
            }
            yield fake_packet
            break  # stop after one for safety in stub mode

    def stop(self) -> None:
        """
        Graceful stop for live capture.
        """
        self._running = False
