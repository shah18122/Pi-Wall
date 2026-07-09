"""Flow tracking and feature extraction.

A flow is a 5-tuple (src, dst, proto, sport, dport). The FlowTable keeps
active flows, expires idle ones, and turns each completed flow into a numeric
feature vector the anomaly detector can score.
"""
import time


class Flow:
    __slots__ = ("key", "src", "dst", "proto", "dport", "start", "last",
                 "packets", "bytes", "syn", "sizes")

    def __init__(self, key, pkt):
        self.key = key
        self.src, self.dst = pkt["src"], pkt["dst"]
        self.proto, self.dport = pkt["proto"], pkt["dport"]
        self.start = self.last = pkt["ts"]
        self.packets = 0
        self.bytes = 0
        self.syn = 0
        self.sizes = []
        self.update(pkt)

    def update(self, pkt):
        self.last = pkt["ts"]
        self.packets += 1
        self.bytes += pkt["length"]
        if "S" in pkt.get("flags", "") and "A" not in pkt.get("flags", ""):
            self.syn += 1
        if len(self.sizes) < 200:
            self.sizes.append(pkt["length"])

    def features(self):
        """Numeric vector for the anomaly model (order matters, keep stable)."""
        dur = max(self.last - self.start, 1e-3)
        mean_sz = sum(self.sizes) / len(self.sizes) if self.sizes else 0.0
        return [
            dur,
            float(self.packets),
            float(self.bytes),
            self.packets / dur,          # packets per second
            self.bytes / dur,            # bytes per second
            mean_sz,
            self.syn / self.packets,     # SYN ratio (half-open indicator)
            float(self.dport),
        ]


def flow_key(pkt):
    return (pkt["src"], pkt["dst"], pkt["proto"], pkt["sport"], pkt["dport"])


class FlowTable:
    def __init__(self, idle_timeout=15):
        self.flows = {}
        self.idle_timeout = idle_timeout

    def add(self, pkt):
        k = flow_key(pkt)
        f = self.flows.get(k)
        if f is None:
            f = self.flows[k] = Flow(k, pkt)
        else:
            f.update(pkt)
        return f

    def expire(self, now=None):
        """Return and remove flows idle longer than the timeout."""
        now = now or time.time()
        dead = [k for k, f in self.flows.items()
                if now - f.last > self.idle_timeout]
        return [self.flows.pop(k) for k in dead]

    def active(self):
        return len(self.flows)
