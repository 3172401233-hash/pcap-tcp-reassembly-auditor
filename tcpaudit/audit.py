"""High-level entry points: run the reassembly audit over a capture."""

from .pcap import iter_packets
from .stream import Reassembler


def audit_packets(packets):
    """Audit an iterable of Packet objects; returns connection reports."""
    r = Reassembler()
    for pkt in packets:
        r.feed(pkt)
    return r.audit()


def audit_pcap(path):
    """Audit a classic pcap file; returns a list of connection reports."""
    return audit_packets(iter_packets(path))
