"""TCP flow state and reassembly logic.

Sequence numbers are handled in a wrap-aware way: all positions are
converted to absolute stream offsets relative to the first data byte
(ISN + 1 when a SYN was observed), using modulo-2**32 arithmetic.

Conflict policy: first-seen bytes win. When a later segment overlaps an
already-reassembled range with *different* content, the old bytes are
kept and a ``conflict`` event is recorded with the old bytes, the new
bytes, the packet index and the stream offset. Identical overlaps are
recorded as ``retransmission`` events.
"""

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10

MOD = 1 << 32


def _seq_delta(a, b):
    """Wrap-aware (a - b) mod 2**32."""
    return (a - b) % MOD


class Direction:
    """One unidirectional byte stream of a TCP connection."""

    def __init__(self, src, sport, dst, dport):
        self.src = src
        self.sport = sport
        self.dst = dst
        self.dport = dport
        self.syn_seen = False
        self.isn = None
        self.base_seq = None        # wire seq number of stream offset 0
        self.intervals = []         # sorted, non-overlapping [start, end, bytearray]
        self.max_end = 0            # highest absolute offset ever delivered
        self.fin_abs = None         # absolute offset of FIN (end of stream)
        self.rst_seen = False
        self.events = []

    # -- event helpers -------------------------------------------------
    def _event(self, etype, packet_index, **kw):
        ev = {"type": etype, "packet": packet_index,
              "direction": "%s:%d" % (self.src, self.sport)}
        ev.update(kw)
        self.events.append(ev)

    # -- flag handling ---------------------------------------------------
    def on_syn(self, packet_index, seq):
        if self.syn_seen:
            self._event("syn_retransmit", packet_index, seq=seq)
            return
        self.syn_seen = True
        self.isn = seq
        self.base_seq = (seq + 1) % MOD

    def on_fin(self, packet_index, seq):
        if self.base_seq is None:
            self.base_seq = (seq + 1) % MOD
        fin_abs = _seq_delta(seq, self.base_seq)
        if self.fin_abs is None:
            self.fin_abs = fin_abs
            self._event("fin", packet_index, offset=fin_abs)

    def on_rst(self, packet_index, seq):
        self.rst_seen = True
        off = _seq_delta(seq, self.base_seq) if self.base_seq is not None else None
        self._event("rst", packet_index, offset=off)

    # -- payload insertion ---------------------------------------------
    def add_segment(self, packet_index, seq, payload):
        """Insert payload; returns nothing, records events as needed."""
        if not payload:
            return  # pure ACK / keep-alive probe without data: nothing to do
        if self.rst_seen:
            self._event("data_after_rst", packet_index,
                        length=len(payload), seq=seq)
            return
        if self.base_seq is None:
            # No SYN observed: anchor the stream at the first data byte.
            self.base_seq = seq
            self._event("data_before_syn", packet_index,
                        length=len(payload), seq=seq)

        start = _seq_delta(seq, self.base_seq)
        end = start + len(payload)

        if self.fin_abs is not None and end > self.fin_abs:
            self._event("data_after_fin", packet_index,
                        offset=self.fin_abs, length=end - self.fin_abs)

        # --- compare against already-reassembled intervals -------------
        covered = []          # merged overlapping (start, end) ranges
        for iv in self.intervals:
            if iv[1] <= start or iv[0] >= end:
                continue
            ov_s = max(start, iv[0])
            ov_e = min(end, iv[1])
            old = bytes(iv[2][ov_s - iv[0]: ov_e - iv[0]])
            new = payload[ov_s - start: ov_e - start]
            if old == new:
                self._event("retransmission", packet_index,
                            offset=ov_s, length=ov_e - ov_s)
            else:
                diffs = [(ov_s + i, old[i], new[i])
                         for i in range(len(old)) if old[i] != new[i]]
                # First-seen-wins: keep old bytes, only report.
                self._event("conflict", packet_index,
                            offset=diffs[0][0],
                            old=old.hex(), new=new.hex(),
                            diffs=[{"offset": o, "old": a, "new": b}
                                   for (o, a, b) in diffs])
            covered.append((ov_s, ov_e))

        # --- keep only the not-yet-covered pieces of the new data ------
        pieces = []
        pos = start
        for cs, ce in covered:
            if pos < cs:
                pieces.append((pos, payload[pos - start: cs - start]))
            pos = max(pos, ce)
        if pos < end:
            pieces.append((pos, payload[pos - start: end - start]))

        if pieces and start < self.max_end:
            self._event("out_of_order", packet_index,
                        offset=start, length=end - start)

        for ps, pdata in pieces:
            self.intervals.append([ps, ps + len(pdata), bytearray(pdata)])
        if pieces:
            self.intervals.sort(key=lambda iv: iv[0])
            merged = []
            for iv in self.intervals:
                if merged and iv[0] <= merged[-1][1]:
                    last = merged[-1]
                    if iv[1] > last[1]:
                        last[2].extend(iv[2][last[1] - iv[0]:])
                        last[1] = iv[1]
                else:
                    merged.append(iv)
            self.intervals = merged
            self.max_end = max(self.max_end, end)

    # -- reporting -------------------------------------------------------
    def regions(self):
        """Contiguous reassembled regions: list of (offset, bytes)."""
        return [(iv[0], bytes(iv[2])) for iv in self.intervals]

    def gaps(self):
        """Byte ranges never received, up to the furthest expected byte."""
        limit = self.max_end
        if self.fin_abs is not None:
            limit = max(limit, self.fin_abs)
        out = []
        pos = 0
        for iv in self.intervals:
            if iv[0] > pos:
                out.append((pos, min(iv[0], limit)))
            pos = max(pos, iv[1])
        if pos < limit:
            out.append((pos, limit))
        return [(s, e) for (s, e) in out if e > s]

    def report(self):
        return {
            "src": self.src, "sport": self.sport,
            "dst": self.dst, "dport": self.dport,
            "syn_seen": self.syn_seen,
            "fin_seen": self.fin_abs is not None,
            "rst_seen": self.rst_seen,
            "regions": self.regions(),
            "gaps": self.gaps(),
            "events": self.events,
        }


class Connection:
    """A TCP connection identified by an unordered 4-tuple."""

    def __init__(self, key):
        self.key = key
        self.directions = {}
        self.first_packet = None
        self.last_packet = None

    def feed(self, pkt):
        dkey = (pkt.src, pkt.sport, pkt.dst, pkt.dport)
        d = self.directions.get(dkey)
        if d is None:
            d = Direction(pkt.src, pkt.sport, pkt.dst, pkt.dport)
            self.directions[dkey] = d
        if self.first_packet is None:
            self.first_packet = pkt.index
        self.last_packet = pkt.index

        if pkt.flags & TCP_SYN:
            d.on_syn(pkt.index, pkt.seq)
        if pkt.payload:
            seq = pkt.seq + 1 if (pkt.flags & TCP_SYN) else pkt.seq
            d.add_segment(pkt.index, seq % MOD, pkt.payload)
        if pkt.flags & TCP_FIN:
            fin_seq = pkt.seq + len(pkt.payload)
            if pkt.flags & TCP_SYN:
                fin_seq += 1
            d.on_fin(pkt.index, fin_seq % MOD)
        if pkt.flags & TCP_RST:
            d.on_rst(pkt.index, pkt.seq)

    def report(self):
        return {
            "key": self.key,
            "first_packet": self.first_packet,
            "last_packet": self.last_packet,
            "directions": [d.report() for d in self.directions.values()],
        }


class Reassembler:
    """Tracks all TCP connections in a capture, keyed by 4-tuple."""

    def __init__(self):
        self.connections = {}

    @staticmethod
    def _key(pkt):
        a = (pkt.src, pkt.sport)
        b = (pkt.dst, pkt.dport)
        return (a, b) if a <= b else (b, a)

    def feed(self, pkt):
        key = self._key(pkt)
        conn = self.connections.get(key)
        if conn is None:
            conn = Connection(key)
            self.connections[key] = conn
        conn.feed(pkt)

    def audit(self):
        return [conn.report() for conn in self.connections.values()]
