import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tcpaudit import audit_pcap
from tcpaudit.stream import TCP_SYN, TCP_FIN, TCP_RST, TCP_PSH, TCP_ACK
from tests.pcapgen import tcp_segment, write_pcap

A_IP, B_IP = "10.0.0.1", "10.0.0.2"
A6, B6 = "fd00::1", "fd00::2"
SPORT, DPORT = 12345, 80
ISN = 1000
PA = TCP_PSH | TCP_ACK


def run_audit(frames):
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        path = f.name
    try:
        write_pcap(path, frames)
        return audit_pcap(path)
    finally:
        os.unlink(path)


def one_direction(report):
    assert len(report) == 1, "expected a single connection"
    dirs = report[0]["directions"]
    assert len(dirs) == 1, "expected a single direction"
    return dirs[0]


def seg(seq, payload, flags=PA, **kw):
    args = dict(src_ip=A_IP, dst_ip=B_IP, sport=SPORT, dport=DPORT,
                seq=seq, flags=flags, payload=payload)
    args.update(kw)
    return tcp_segment(**args)


class TestBasic(unittest.TestCase):
    def test_in_order_stream(self):
        frames = [
            seg(ISN, b"", flags=TCP_SYN),
            seg(ISN + 1, b"hello "),
            seg(ISN + 7, b"world"),
            seg(ISN + 12, b"", flags=TCP_FIN | TCP_ACK),
        ]
        d = one_direction(run_audit(frames))
        self.assertEqual(d["regions"], [(0, b"hello world")])
        self.assertEqual(d["gaps"], [])
        self.assertTrue(d["syn_seen"])
        self.assertTrue(d["fin_seen"])
        self.assertEqual(d["events"], [{"type": "fin", "packet": 3,
                                        "direction": "10.0.0.1:12345",
                                        "offset": 11}])

    def test_pure_ack_ignored(self):
        frames = [
            seg(ISN, b"", flags=TCP_SYN),
            seg(ISN + 1, b"abc"),
            seg(ISN + 4, b"", flags=TCP_ACK),   # pure ACK, no payload
            seg(ISN + 4, b"def"),
        ]
        d = one_direction(run_audit(frames))
        self.assertEqual(d["regions"], [(0, b"abcdef")])
        self.assertEqual(d["events"], [])


class TestOrdering(unittest.TestCase):
    def test_out_of_order(self):
        frames = [
            seg(ISN, b"", flags=TCP_SYN),
            seg(ISN + 4, b"def"),   # second chunk arrives first
            seg(ISN + 1, b"abc"),
        ]
        d = one_direction(run_audit(frames))
        self.assertEqual(d["regions"], [(0, b"abcdef")])
        self.assertEqual(d["gaps"], [])
        types = [e["type"] for e in d["events"]]
        self.assertIn("out_of_order", types)

    def test_gap_reported(self):
        frames = [
            seg(ISN, b"", flags=TCP_SYN),
            seg(ISN + 1, b"abc"),
            seg(ISN + 10, b"xyz"),  # bytes 3..9 missing
        ]
        d = one_direction(run_audit(frames))
        self.assertEqual(d["regions"], [(0, b"abc"), (9, b"xyz")])
        self.assertEqual(d["gaps"], [(3, 9)])

    def test_duplicate_segment(self):
        frames = [
            seg(ISN, b"", flags=TCP_SYN),
            seg(ISN + 1, b"abc"),
            seg(ISN + 1, b"abc"),   # exact retransmission
        ]
        d = one_direction(run_audit(frames))
        self.assertEqual(d["regions"], [(0, b"abc")])
        self.assertEqual([e["type"] for e in d["events"]], ["retransmission"])
        self.assertEqual(d["events"][0]["packet"], 2)
        self.assertEqual(d["events"][0]["offset"], 0)


class TestOverlap(unittest.TestCase):
    def test_overlap_identical(self):
        frames = [
            seg(ISN, b"", flags=TCP_SYN),
            seg(ISN + 1, b"abcdef"),
            seg(ISN + 3, b"cdefgh"),  # overlaps "cdef", extends with "gh"
        ]
        d = one_direction(run_audit(frames))
        self.assertEqual(d["regions"], [(0, b"abcdefgh")])
        types = [e["type"] for e in d["events"]]
        self.assertIn("retransmission", types)
        self.assertNotIn("conflict", types)

    def test_overlap_conflict_first_wins(self):
        frames = [
            seg(ISN, b"", flags=TCP_SYN),
            seg(ISN + 1, b"abcdef"),
            seg(ISN + 3, b"cdXYgh"),  # bytes 4..5 differ: 'ef' vs 'XY'
        ]
        d = one_direction(run_audit(frames))
        # first-seen bytes are kept
        self.assertEqual(d["regions"], [(0, b"abcdefgh")])
        conflicts = [e for e in d["events"] if e["type"] == "conflict"]
        self.assertEqual(len(conflicts), 1)
        c = conflicts[0]
        self.assertEqual(c["packet"], 2)
        self.assertEqual(c["offset"], 4)
        self.assertEqual(c["old"], "63646566")   # b"cdef"
        self.assertEqual(c["new"], "63645859")   # b"cdXY"
        self.assertEqual(c["diffs"], [
            {"offset": 4, "old": ord("e"), "new": ord("X")},
            {"offset": 5, "old": ord("f"), "new": ord("Y")},
        ])


class TestWraparound(unittest.TestCase):
    def test_sequence_wrap(self):
        isn = 0xFFFFFFFE
        frames = [
            seg(isn, b"", flags=TCP_SYN),
            seg(isn + 1, b"ab"),          # seqs 0xFFFFFFFF, 0x00000000
            seg(1, b"cd"),                # continues after wrap
            seg(3, b"", flags=TCP_FIN | TCP_ACK),
        ]
        d = one_direction(run_audit(frames))
        self.assertEqual(d["regions"], [(0, b"abcd")])
        self.assertEqual(d["gaps"], [])


class TestConnectionState(unittest.TestCase):
    def test_data_without_syn(self):
        frames = [
            seg(5000, b"abc"),
            seg(5003, b"def"),
        ]
        d = one_direction(run_audit(frames))
        self.assertFalse(d["syn_seen"])
        self.assertEqual(d["regions"], [(0, b"abcdef")])
        self.assertEqual(d["events"][0]["type"], "data_before_syn")

    def test_rst_truncates_stream(self):
        frames = [
            seg(ISN, b"", flags=TCP_SYN),
            seg(ISN + 1, b"abc"),
            seg(ISN + 4, b"", flags=TCP_RST),
            seg(ISN + 4, b"def"),   # arrives after RST: must be rejected
        ]
        d = one_direction(run_audit(frames))
        self.assertTrue(d["rst_seen"])
        self.assertEqual(d["regions"], [(0, b"abc")])
        types = [e["type"] for e in d["events"]]
        self.assertIn("rst", types)
        self.assertIn("data_after_rst", types)

    def test_data_after_fin_flagged(self):
        frames = [
            seg(ISN, b"", flags=TCP_SYN),
            seg(ISN + 1, b"abc"),
            seg(ISN + 4, b"", flags=TCP_FIN | TCP_ACK),
            seg(ISN + 4, b"def"),
        ]
        d = one_direction(run_audit(frames))
        types = [e["type"] for e in d["events"]]
        self.assertIn("data_after_fin", types)


class TestTopology(unittest.TestCase):
    def test_bidirectional_single_connection(self):
        frames = [
            seg(ISN, b"", flags=TCP_SYN),
            tcp_segment(B_IP, A_IP, DPORT, SPORT, 7000, flags=TCP_SYN),
            seg(ISN + 1, b"request"),
            tcp_segment(B_IP, A_IP, DPORT, SPORT, 7001, payload=b"response"),
        ]
        report = run_audit(frames)
        self.assertEqual(len(report), 1)
        self.assertEqual(len(report[0]["directions"]), 2)
        payloads = sorted(
            d["regions"][0][1] for d in report[0]["directions"])
        self.assertEqual(payloads, [b"request", b"response"])

    def test_ipv6_flow(self):
        frames = [
            tcp_segment(A6, B6, SPORT, DPORT, ISN, flags=TCP_SYN, ipv6=True),
            tcp_segment(A6, B6, SPORT, DPORT, ISN + 1, payload=b"v6data", ipv6=True),
        ]
        d = one_direction(run_audit(frames))
        self.assertEqual(d["regions"], [(0, b"v6data")])


if __name__ == "__main__":
    unittest.main()
