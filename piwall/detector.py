"""Threat detection — the AI core of Pi-Wall.

Two complementary layers:

  HeuristicDetector — deterministic, per-source sliding-window rules that catch
      well-known attack shapes (port scan, SYN flood, volumetric flood). Fast,
      explainable, zero false-negatives on textbook attacks.

  AnomalyDetector — an unsupervised IsolationForest (scikit-learn) trained on a
      warm-up window of normal flow features. It flags flows that don't look
      like anything it learned, catching novel/zero-day behaviour the fixed
      rules would miss.

Each returns Threat records; the engine fuses them into a 0-100 score.
"""
import collections
import time


class Threat:
    def __init__(self, kind, src, severity, detail, score):
        self.kind = kind          # e.g. "port_scan", "anomaly"
        self.src = src
        self.severity = severity  # low | medium | high | critical
        self.detail = detail
        self.score = score        # 0..100 contribution
        self.ts = time.time()

    def to_dict(self):
        return {"kind": self.kind, "src": self.src, "severity": self.severity,
                "detail": self.detail, "score": self.score, "ts": self.ts}


class HeuristicDetector:
    def __init__(self, cfg):
        self.scan_threshold = cfg["scan_threshold"]
        self.synflood_threshold = cfg["synflood_threshold"]
        self.volumetric_pps = cfg["volumetric_pps"]
        self.window = cfg["window_seconds"]
        # per-source rolling event log: deque of (ts, dst, dport, is_syn)
        self.events = collections.defaultdict(collections.deque)

    def observe(self, pkt):
        """Record a packet and return a list of Threats it triggers."""
        src = pkt["src"]
        now = pkt["ts"]
        dq = self.events[src]
        dq.append((now, pkt["dst"], pkt["dport"],
                   "S" in pkt.get("flags", "") and "A" not in pkt.get("flags", "")))
        cutoff = now - self.window
        while dq and dq[0][0] < cutoff:
            dq.popleft()

        threats = []
        distinct_ports = {d for _, _, d, _ in dq}
        if len(distinct_ports) >= self.scan_threshold:
            threats.append(Threat(
                "port_scan", src, "high",
                f"{len(distinct_ports)} distinct dst ports in {self.window}s "
                "(horizontal port scan)", 75))

        syns_to = collections.Counter(dst for _, dst, _, is_syn in dq if is_syn)
        if syns_to:
            dst, n = syns_to.most_common(1)[0]
            if n >= self.synflood_threshold:
                threats.append(Threat(
                    "syn_flood", src, "critical",
                    f"{n} half-open SYNs to {dst} in {self.window}s "
                    "(SYN flood / DoS)", 90))

        pps = len(dq) / self.window
        if pps >= self.volumetric_pps:
            threats.append(Threat(
                "volumetric", src, "high",
                f"{pps:.0f} packets/sec sustained (volumetric flood)", 80))
        return threats


class AnomalyDetector:
    """IsolationForest over flow feature vectors."""

    def __init__(self, cfg):
        self.warmup_flows = cfg["warmup_flows"]
        self.contamination = cfg["anomaly_contamination"]
        self._buf = []
        self.model = None
        self.scaler = None
        self.trained = False

    def _fit(self):
        import numpy as np
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler
        X = np.array(self._buf, dtype=float)
        self.scaler = StandardScaler().fit(X)
        self.model = IsolationForest(
            n_estimators=150, contamination=self.contamination,
            random_state=42).fit(self.scaler.transform(X))
        self.trained = True

    def score_flow(self, flow):
        """Return a Threat if the flow is anomalous, else None.

        During warm-up it just collects normal-looking features and trains
        once enough have accumulated.
        """
        feats = flow.features()
        if not self.trained:
            self._buf.append(feats)
            if len(self._buf) >= self.warmup_flows:
                self._fit()
            return None

        import numpy as np
        x = self.scaler.transform(np.array([feats], dtype=float))
        pred = self.model.predict(x)[0]            # -1 = anomaly
        raw = self.model.score_samples(x)[0]       # lower = more anomalous
        if pred == -1:
            # map raw score to a 40..85 severity band
            sev = max(40, min(85, int(60 - raw * 25)))
            return Threat(
                "anomaly", flow.src,
                "high" if sev >= 65 else "medium",
                f"flow to :{flow.dport} deviates from learned baseline "
                f"(ML anomaly score {raw:+.2f})", sev)
        return None
