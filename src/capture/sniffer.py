from typing import Generator, Optional, Dict, Any
import time
import socket

# scapy for live capture
from scapy.all import sniff, TCP, UDP, IP  # type: ignore

# pyshark for offline pcap read
import pyshark  # type: ignore


class PacketSniffer:
    """
    PacketSniffer captures packets from a live interface or an offline pcap.

    Output is a generator of PacketRecord dicts:

    {
        "timestamp": float,        # epoch seconds
        "src_ip": str,
        "dst_ip": str,
        "src_port": int | None,
        "dst_port": int | None,
        "protocol": str,           # "TCP" | "UDP" | "OTHER"
        "pkt_len": int,
        "tcp_flags": dict | None   # {"SYN":0/1,"ACK":0/1,"FIN":0/1,"PSH":0/1} or None
    }

    Notes:
    - Live capture usually requires root/admin privileges to sniff an interface.
    - Offline capture (pcap_file) does not.
    """

    def __init__(
        self,
        iface: Optional[str] = None,
        pcap_file: Optional[str] = None,
        capture_filter: Optional[str] = None,
        snaplen: int = 96,
        promisc: bool = True,
        timeout: Optional[int] = None,
    ):
        """
        iface: network interface like "eth0", "wlan0"
        pcap_file: offline .pcap or .pcapng path
        capture_filter: BPF filter like "tcp or udp"
        snaplen: max bytes per packet to capture (live mode)
        promisc: promiscuous mode if iface allows
        timeout: stop sniffing after N seconds in live mode (None means no stop)

        For offline mode, iface is ignored and we iterate over pcap_file.
        For live mode, pcap_file must be None.
        """
        self.iface = iface
        self.pcap_file = pcap_file
        self.capture_filter = capture_filter
        self.snaplen = snaplen
        self.promisc = promisc
        self.timeout = timeout

        self._running = False

    def start_stream(self) -> Generator[Dict[str, Any], None, None]:
        """
        Unified generator interface.
        Chooses offline or live path.
        Yields PacketRecord dicts.

        Caller controls when to break.
        """
        self._running = True

        if self.pcap_file:
            # offline mode using pyshark.FileCapture
            for pkt in self._iter_offline():
                if not self._running:
                    break
                yield pkt
        else:
            # live mode using scapy.sniff
            # scapy sniff returns a list when count>0 or on timeout,
            # but prn can be used for streaming callbacks.
            # We wrap prn to push into a local queue/yield pattern.
            for pkt in self._iter_live():
                if not self._running:
                    break
                yield pkt

    def stop(self) -> None:
        """
        Signal capture loop to end.
        """
        self._running = False

    #
    # Internal helpers
    #

    def _normalize_tcp_flags(self, scapy_pkt) -> Optional[Dict[str, int]]:
        """
        Extract SYN/ACK/FIN/PSH flags from TCP if present.
        """
        if TCP in scapy_pkt:
            flags_val = int(scapy_pkt[TCP].flags)
            # scapy uses bit flags
            # SYN=0x02, ACK=0x10, FIN=0x01, PSH=0x08
            return {
                "SYN": 1 if flags_val & 0x02 else 0,
                "ACK": 1 if flags_val & 0x10 else 0,
                "FIN": 1 if flags_val & 0x01 else 0,
                "PSH": 1 if flags_val & 0x08 else 0,
            }
        return None

    def _pktrecord_from_scapy(self, pkt) -> Optional[Dict[str, Any]]:
        """
        Convert a scapy packet to PacketRecord.
        Returns None if missing IP layer.
        """
        if IP not in pkt:
            return None

        ts = float(pkt.time)
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        length = int(len(pkt))

        if TCP in pkt:
            proto = "TCP"
            src_port = int(pkt[TCP].sport)
            dst_port = int(pkt[TCP].dport)
            flags = self._normalize_tcp_flags(pkt)
        elif UDP in pkt:
            proto = "UDP"
            src_port = int(pkt[UDP].sport)
            dst_port = int(pkt[UDP].dport)
            flags = None
        else:
            proto = "OTHER"
            src_port = None
            dst_port = None
            flags = None

        return {
            "timestamp": ts,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": proto,
            "pkt_len": length,
            "tcp_flags": flags,
        }

    def _iter_live(self) -> Generator[Dict[str, Any], None, None]:
        """
        Live capture generator using scapy.sniff.
        We manually drive sniff() in small batches so we can yield and honor stop().
        """
        # scapy.sniff does not stream-yield by default
        # so we call it in a loop with count=1 to simulate a generator
        # This is inefficient for huge throughput but fine for demo and testing

        while self._running:
            pkts = sniff(
                iface=self.iface,
                filter=self.capture_filter,
                count=1,
                timeout=self.timeout,
                promisc=self.promisc,
                # scapy ignores snaplen in sniff(), but we keep param for future use
            )

            if not pkts:
                # timeout or no traffic
                continue

            for p in pkts:
                rec = self._pktrecord_from_scapy(p)
                if rec is not None:
                    yield rec

    def _iter_offline(self) -> Generator[Dict[str, Any], None, None]:
        """
        Offline capture generator using pyshark.FileCapture.
        pyshark gives higher level protocol parsing of a stored .pcap.
        We convert each pyshark packet into our PacketRecord format.
        """
        cap = pyshark.FileCapture(
            self.pcap_file,
            display_filter=self.capture_filter,  # Wireshark filter syntax
            keep_packets=False,
        )

        for pkt in cap:
            if not self._running:
                break

            # timestamp
            try:
                ts = float(pkt.sniff_timestamp)
            except Exception:
                ts = time.time()

            # packet length
            if hasattr(pkt, "length"):
                try:
                    length = int(pkt.length)
                except Exception:
                    length = 0
            else:
                length = 0

            # defaults
            src_ip = None
            dst_ip = None
            src_port = None
            dst_port = None
            proto = "OTHER"
            flags = None

            # IP layer
            if hasattr(pkt, "ip"):
                src_ip = getattr(pkt.ip, "src", None)
                dst_ip = getattr(pkt.ip, "dst", None)

            # TCP
            if hasattr(pkt, "tcp"):
                proto = "TCP"
                src_port = safe_int(getattr(pkt.tcp, "srcport", None))
                dst_port = safe_int(getattr(pkt.tcp, "dstport", None))
                flags = {
                    "SYN": safe_flag(getattr(pkt.tcp, "flags_syn", None)),
                    "ACK": safe_flag(getattr(pkt.tcp, "flags_ack", None)),
                    "FIN": safe_flag(getattr(pkt.tcp, "flags_fin", None)),
                    "PSH": safe_flag(getattr(pkt.tcp, "flags_push", None)),
                }

            # UDP
            elif hasattr(pkt, "udp"):
                proto = "UDP"
                src_port = safe_int(getattr(pkt.udp, "srcport", None))
                dst_port = safe_int(getattr(pkt.udp, "dstport", None))
                flags = None

            # if not IPv4 we skip because the rest of pipeline expects IP fields
            if src_ip is None or dst_ip is None:
                continue

            rec = {
                "timestamp": ts,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": proto,
                "pkt_len": length,
                "tcp_flags": flags,
            }

            yield rec



def safe_int(x):
    try:
        return int(x)
    except Exception:
        return None

def safe_flag(val):
    """
    Convert pyshark TCP flag fields into 0/1.
    pyshark sometimes returns:
    - "1"
    - "0"
    - "True"
    - "False"
    - True / False (actual booleans)
    We normalize all of that to int 0 or 1.
    """
    if isinstance(val, bool):
        return 1 if val else 0
    if val is None:
        return 0
    s = str(val).strip().lower()
    if s in ("1", "true", "yes", "y", "set"):
        return 1
    return 0
