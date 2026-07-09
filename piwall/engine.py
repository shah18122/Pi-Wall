"""Pi-Wall engine — wires capture → flows → firewall → AI → enforcement.

Runs the capture loop in a background thread and maintains thread-safe shared
state (counters, recent packets, threats, blocklist) that the dashboard reads.
On launch it immediately begins tracking ALL traffic on the chosen source.
"""
import collections
import threading
import time

from .capture import ScapySource, SimulatedSource
from .detector import AnomalyDetector, HeuristicDetector
from .firewall import Firewall
from .ai_advisor import AIAdvisor
from .flows import FlowTable


class PiWallEngine:
    def __init__(self, config, rules, simulate=True, iface=None):
        self.cfg = config
        det = config["detection"]
        self.firewall = Firewall(rules, mode=config["enforcement"]["mode"])
        self.heur = HeuristicDetector(det)
        self.anomaly = AnomalyDetector(det)
        self.advisor = AIAdvisor(config["ai_advisor"])
        self.flows = FlowTable()
        self.block_score = det["block_score"]
        self._scored = set()          # flow keys already sent to the ML model
        self.min_flow_packets = 4     # ignore single-packet noise for anomaly ML
        self._last_threat = {}        # (src,kind) -> ts, for de-duplication
        self.threat_cooldown = 5      # seconds between repeats of the same alert

        if simulate:
            self.source = SimulatedSource()
        else:
            self.source = ScapySource(
                iface or config["capture"]["interface"],
                config["capture"]["bpf_filter"])

        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread = None
        self.started_at = None

        # shared state
        self.stats = {"packets": 0, "bytes": 0}
        self.recent = collections.deque(maxlen=40)      # recent packets
        self.threats = collections.deque(maxlen=40)     # recent threats
        self.talkers = collections.Counter()            # bytes per src
        self._threat_scores = collections.defaultdict(float)

    # ---- lifecycle ----
    def start(self):
        self.started_at = time.time()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    # ---- main loop ----
    def _run(self):
        last_score = time.time()
        for pkt in self.source.stream(self._stop):
            if self._stop.is_set():
                break
            self._process(pkt)
            if time.time() - last_score > 2:
                self._score_flows()
                last_score = time.time()

    def _process(self, pkt):
        action, reason = self.firewall.evaluate(pkt)
        flow = self.flows.add(pkt)
        threats = self.heur.observe(pkt)

        with self._lock:
            self.stats["packets"] += 1
            self.stats["bytes"] += pkt["length"]
            self.talkers[pkt["src"]] += pkt["length"]
            self.recent.appendleft({
                "ts": pkt["ts"], "src": pkt["src"], "dst": pkt["dst"],
                "proto": pkt["proto"], "dport": pkt["dport"],
                "length": pkt["length"], "action": action, "reason": reason})
            for t in threats:
                self._record_threat(t)

    def _score_flows(self):
        """Score meaningful (multi-packet) flows once — active or expired.

        Single-packet flows are noise for the ML model (and are already covered
        by the heuristic layer), so only flows with enough packets are learned
        from and scored. This is what lets the anomaly model isolate a genuine
        outlier (e.g. bulk exfiltration) instead of normal one-shot requests.
        """
        candidates = [f for f in list(self.flows.flows.values())
                      if f.packets >= self.min_flow_packets
                      and f.key not in self._scored]
        candidates += [f for f in self.flows.expire()
                       if f.packets >= self.min_flow_packets
                       and f.key not in self._scored]
        for flow in candidates:
            self._scored.add(flow.key)
            t = self.anomaly.score_flow(flow)
            if t:
                with self._lock:
                    self._record_threat(t)

    def _record_threat(self, threat):
        """Assumes caller holds the lock."""
        key = (threat.src, threat.kind)
        now = threat.ts
        if now - self._last_threat.get(key, 0) < self.threat_cooldown:
            # still accrue score for auto-blocking, but don't spam the feed
            self._threat_scores[threat.src] += threat.score * 0.1
            return
        self._last_threat[key] = now
        self._threat_scores[threat.src] += threat.score
        entry = threat.to_dict()
        # ask the GenAI advisor for serious threats
        if threat.score >= 60:
            advice = self.advisor.explain(threat)
            if advice:
                entry["advice"] = advice
        # auto-block when accumulated score crosses the threshold
        if self._threat_scores[threat.src] >= self.block_score:
            if self.firewall.block(threat.src, threat.kind):
                entry["blocked"] = True
        self.threats.appendleft(entry)

    # ---- read-only snapshot for the dashboard ----
    def snapshot(self):
        with self._lock:
            fw = self.firewall.stats
            return {
                "uptime": round(time.time() - (self.started_at or time.time()), 1),
                "mode": self.firewall.mode,
                "packets": self.stats["packets"],
                "bytes": self.stats["bytes"],
                "allowed": fw["allow"],
                "denied": fw["deny"],
                "active_flows": self.flows.active(),
                "anomaly_trained": self.anomaly.trained,
                "blocked": [{"ip": ip, **meta}
                            for ip, meta in self.firewall.blocked.items()],
                "threats": list(self.threats)[:20],
                "recent": list(self.recent)[:20],
                "top_talkers": [{"src": s, "bytes": b}
                                for s, b in self.talkers.most_common(5)],
            }
