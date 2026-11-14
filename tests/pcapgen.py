"""Helpers to synthesize classic pcap files containing TCP packets."""

import struct

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10

_MAC = b"\x02\x00\x00\x00\x00\x01"


def tcp_segment(src_ip, dst_ip, sport, dport, seq, ack=0,
                flags=TCP_PSH | TCP_ACK, payload=b"", ipv6=False):
    """Build one Ethernet/IPv4-or-IPv6/TCP frame (checksums left zero)."""
    tcp = struct.pack("!HHII", sport, dport, seq & 0xFFFFFFFF, ack)
    tcp += struct.pack("!BBHHH", 5 << 4, flags, 65535, 0, 0)
    tcp += payload
    if ipv6:
        src = bytes(int(p, 16) for p in src_ip.split(":")) if False else _v6(src_ip)
        dst = _v6(dst_ip)
        ip = struct.pack("!IHBB", 6 << 28, len(tcp), 6, 64) + src + dst
        eth_type = 0x86DD
    else:
        src = bytes(int(p) for p in src_ip.split("."))
        dst = bytes(int(p) for p in dst_ip.split("."))
        total = 20 + len(tcp)
        ip = struct.pack("!BBHHHBBH", 0x45, 0, total, 0, 0, 64, 6, 0) + src + dst
        eth_type = 0x0800
    return _MAC + _MAC + struct.pack("!H", eth_type) + ip + tcp


def _v6(addr):
    """Expand a (possibly ::-compressed) IPv6 address to 16 bytes."""
    if "::" in addr:
        left, _, right = addr.partition("::")
        left_parts = left.split(":") if left else []
        right_parts = right.split(":") if right else []
        missing = 8 - len(left_parts) - len(right_parts)
        parts = left_parts + ["0"] * missing + right_parts
    else:
        parts = addr.split(":")
    return b"".join(struct.pack("!H", int(p, 16)) for p in parts)


def write_pcap(path, frames):
    """Write frames (bytes) to a little-endian classic pcap file."""
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiiii", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, frame in enumerate(frames):
            f.write(struct.pack("<IIII", 1700000000 + i, 0, len(frame), len(frame)))
            f.write(frame)
