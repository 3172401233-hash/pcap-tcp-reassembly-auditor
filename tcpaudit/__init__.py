"""Offline TCP reassembly auditing library.

Parses IPv4/IPv6 + TCP packets from a PCAP file (no application protocol
parsing), tracks flows by 4-tuple, and audits reassembly: sequence
wraparound, pure ACKs, retransmissions, out-of-order delivery, FIN/RST,
gaps, and conflicting bytes for the same byte range.
"""

from .stream import Reassembler, Connection, Direction
from .pcap import Packet, iter_packets
from .audit import audit_pcap, audit_packets

__all__ = [
    "Reassembler",
    "Connection",
    "Direction",
    "Packet",
    "iter_packets",
    "audit_pcap",
    "audit_packets",
]
