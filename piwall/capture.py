"""Packet capture sources.

Two interchangeable sources yield the same normalized packet dict:
  {ts, src, dst, proto, sport, dport, length, flags}

  * ScapySource     — live capture from a real interface (needs root).
  * SimulatedSource — synthetic but realistic traffic that MIXES normal flows
                      with injected attacks (port scan, SYN flood, exfil),
                      so Pi-Wall can be demonstrated and tested on any machine.
"""
import math
import time


def _pseudo_rand(seed):
    """Deterministic 0..1 from an integer seed (no Math.random needed)."""
    x = math.sin(seed * 12.9898) * 43758.5453
    return x - math.floor(x)


class ScapySource:
    """Live capture via scapy. Requires root and a real interface."""

    def __init__(self, interface="eth0", bpf_filter="ip"):
        self.interface = interface
        self.bpf_filter = bpf_filter

    def stream(self, stop):
        from scapy.all import sniff, IP, TCP, UDP  # noqa: local import

        def handle(pkt):
            if IP not in pkt:
                return None
            ip = pkt[IP]
            proto, sport, dport, flags = "other", 0, 0, ""
            if TCP in pkt:
                proto = "tcp"
                sport, dport = int(pkt[TCP].sport), int(pkt[TCP].dport)
                flags = str(pkt[TCP].flags)
            elif UDP in pkt:
                proto = "udp"
                sport, dport = int(pkt[UDP].sport), int(pkt[UDP].dport)
            return {"ts": time.time(), "src": ip.src, "dst": ip.dst,
                    "proto": proto, "sport": sport, "dport": dport,
                    "length": int(len(pkt)), "flags": flags}

        # sniff in small bursts so we can honour the stop flag
        while not stop.is_set():
            pkts = sniff(iface=self.interface, filter=self.bpf_filter,
                         timeout=1, store=True)
            for p in pkts:
                out = handle(p)
                if out:
                    yield out


class SimulatedSource:
    """Synthetic traffic generator: normal background + timed attacks."""

    NORMAL_DPORTS = [443, 443, 443, 80, 53, 53, 123, 8080]
    INTERNAL = ["10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.1.20"]
    EXTERNAL = ["203.0.113.9", "198.51.100.7", "192.0.2.44", "185.220.101.5"]
    SERVER = "10.0.0.2"

    def __init__(self, rate=120, attacks=True):
        self.rate = rate            # packets/sec target
        self.attacks = attacks
        self._i = 0

    def _normal(self, r1, r2):
        internal = self.INTERNAL[int(r1 * len(self.INTERNAL)) % len(self.INTERNAL)]
        dport = self.NORMAL_DPORTS[int(r2 * len(self.NORMAL_DPORTS))
                                   % len(self.NORMAL_DPORTS)]
        proto = "udp" if dport in (53, 123) else "tcp"
        # Reuse a small pool of source ports so normal traffic forms real,
        # multi-packet connections (as genuine web/DNS sessions do).
        sport = 20000 + int(r1 * 6)
        return {"src": internal, "dst": self.SERVER, "proto": proto,
                "sport": sport, "dport": dport,
                "length": 80 + int(r2 * 260),      # tight, human-web-like sizes
                "flags": "S" if r2 < 0.15 else "PA"}

    def stream(self, stop):
        start = time.time()
        while not stop.is_set():
            now = time.time()
            elapsed = now - start
            r1, r2 = _pseudo_rand(self._i), _pseudo_rand(self._i * 7 + 3)

            pkt = self._normal(r1, r2)

            # ---- injected attacks (time-boxed so the demo shows detection) ----
            if self.attacks:
                if 5 < elapsed < 9:                    # port scan
                    pkt = {"src": "185.220.101.5", "dst": self.SERVER,
                           "proto": "tcp", "sport": 40000,
                           "dport": (self._i % 1000) + 1, "length": 40,
                           "flags": "S"}
                elif 12 < elapsed < 16:                # SYN flood
                    pkt = {"src": "203.0.113.9", "dst": self.SERVER,
                           "proto": "tcp", "sport": 1024 + (self._i % 50000),
                           "dport": 80, "length": 44, "flags": "S"}
                elif 19 < elapsed < 22:                # data exfiltration
                    pkt = {"src": "10.0.0.7", "dst": "198.51.100.7",
                           "proto": "tcp", "sport": 54000, "dport": 4444,
                           "length": 1400, "flags": "PA"}

            pkt["ts"] = now
            self._i += 1
            yield pkt
            time.sleep(1.0 / max(self.rate, 1))
