"""Minimal classic-PCAP reader and IPv4/IPv6/TCP packet parser.

Only link-layer type Ethernet (LINKTYPE_ETHERNET = 1) is decoded, with
optional 802.1Q VLAN tags. IPv6 extension headers (hop-by-hop, routing,
destination options, fragment) are skipped. No application protocol
parsing is performed.
"""

import struct
from dataclasses import dataclass

LINKTYPE_ETHERNET = 1

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_QINQ = 0x88A8

IPPROTO_TCP = 6
_IPV6_EXT_HEADERS = {0, 43, 44, 60}  # hbh, routing, fragment, dest-opts


@dataclass
class Packet:
    index: int          # 0-based packet number in the capture
    ts: float           # timestamp in seconds
    src: str
    dst: str
    sport: int
    dport: int
    seq: int
    ack: int
    flags: int
    payload: bytes


class PcapError(Exception):
    pass


def _read_global_header(f):
    magic = f.read(4)
    if len(magic) < 4:
        raise PcapError("truncated pcap global header")
    if magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    elif magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        endian = "<" if magic[0] == 0x4D else ">"
    else:
        raise PcapError("not a classic pcap file (pcapng is unsupported)")
    rest = f.read(20)
    if len(rest) < 20:
        raise PcapError("truncated pcap global header")
    _, _, _, _, _, network = struct.unpack(endian + "HHiiii", rest)
    return endian, network


def _parse_ethernet(data):
    if len(data) < 14:
        return None
    ethertype = struct.unpack("!H", data[12:14])[0]
    off = 14
    while ethertype in (ETHERTYPE_VLAN, ETHERTYPE_QINQ):
        if len(data) < off + 4:
            return None
        ethertype = struct.unpack("!H", data[off + 2:off + 4])[0]
        off += 4
    return ethertype, data[off:]


def _parse_ipv4(data):
    if len(data) < 20:
        return None
    ihl = (data[0] & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        return None
    total_len = struct.unpack("!H", data[2:4])[0]
    proto = data[9]
    src = ".".join(str(b) for b in data[12:16])
    dst = ".".join(str(b) for b in data[16:20])
    payload = data[ihl:total_len] if total_len >= ihl else b""
    return proto, src, dst, payload


def _parse_ipv6(data):
    if len(data) < 40:
        return None
    payload_len = struct.unpack("!H", data[4:6])[0]
    next_header = data[6]
    src = ":".join("%x" % struct.unpack("!H", data[8 + i:10 + i])[0]
                   for i in range(0, 16, 2))
    dst = ":".join("%x" % struct.unpack("!H", data[24 + i:26 + i])[0]
                   for i in range(0, 16, 2))
    off = 40
    end = 40 + payload_len
    while next_header in _IPV6_EXT_HEADERS:
        if next_header == 44:  # fragment header: fixed 8 bytes
            hdr_len = 8
        else:
            if len(data) < off + 2:
                return None
            hdr_len = (data[off + 1] + 1) * 8
        if len(data) < off + hdr_len:
            return None
        next_header = data[off]
        off += hdr_len
    return next_header, src, dst, data[off:end]


def _parse_tcp(data):
    if len(data) < 20:
        return None
    sport, dport, seq, ack = struct.unpack("!HHII", data[:12])
    data_off = (data[12] >> 4) * 4
    if data_off < 20 or len(data) < data_off:
        return None
    flags = data[13]
    return sport, dport, seq, ack, flags, data[data_off:]


def parse_frame(index, ts, linktype, frame):
    """Parse one captured frame into a Packet, or None if not TCP/IP."""
    if linktype != LINKTYPE_ETHERNET:
        return None
    parsed = _parse_ethernet(frame)
    if parsed is None:
        return None
    ethertype, ip_data = parsed
    if ethertype == ETHERTYPE_IPV4:
        ipp = _parse_ipv4(ip_data)
    elif ethertype == ETHERTYPE_IPV6:
        ipp = _parse_ipv6(ip_data)
    else:
        return None
    if ipp is None:
        return None
    proto, src, dst, tcp_data = ipp
    if proto != IPPROTO_TCP:
        return None
    tcpp = _parse_tcp(tcp_data)
    if tcpp is None:
        return None
    sport, dport, seq, ack, flags, payload = tcpp
    return Packet(index=index, ts=ts, src=src, dst=dst,
                  sport=sport, dport=dport, seq=seq, ack=ack,
                  flags=flags, payload=payload)


def iter_packets(path):
    """Yield Packet objects for every TCP/IPv4/IPv6 frame in a pcap file."""
    with open(path, "rb") as f:
        endian, linktype = _read_global_header(f)
        index = 0
        while True:
            hdr = f.read(16)
            if not hdr:
                return
            if len(hdr) < 16:
                raise PcapError("truncated packet header")
            ts_sec, ts_frac, incl_len, _ = struct.unpack(endian + "IIII", hdr)
            data = f.read(incl_len)
            if len(data) < incl_len:
                raise PcapError("truncated packet data")
            pkt = parse_frame(index, ts_sec + ts_frac / 1e6, linktype, data)
            if pkt is not None:
                yield pkt
            index += 1
