"""Unit tests for Pi-Wall's detection and firewall logic."""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from piwall.config import load_config, load_rules
from piwall.detector import HeuristicDetector, AnomalyDetector
from piwall.firewall import Firewall
from piwall.flows import FlowTable


def _pkt(src, dst, dport, proto="tcp", flags="S", length=60, ts=None):
    return {"src": src, "dst": dst, "proto": proto, "sport": 40000,
            "dport": dport, "flags": flags, "length": length,
            "ts": ts if ts is not None else time.time()}


def test_firewall_rules_and_default():
    fw = Firewall(load_rules())
    assert fw.evaluate(_pkt("203.0.113.9", "10.0.0.2", 443))[0] == "allow"
    assert fw.evaluate(_pkt("203.0.113.9", "10.0.0.2", 22))[0] == "deny"   # external SSH
    assert fw.evaluate(_pkt("10.0.0.5", "10.0.0.2", 22))[0] == "allow"     # internal SSH
    assert fw.evaluate(_pkt("203.0.113.9", "10.0.0.2", 23))[0] == "deny"   # telnet


def test_firewall_block_and_never_block():
    fw = Firewall(load_rules())
    assert fw.block("203.0.113.9", "port_scan") is True
    assert fw.evaluate(_pkt("203.0.113.9", "10.0.0.2", 443))[0] == "deny"  # now blocklisted
    assert fw.block("127.0.0.1", "x") is False        # never-block honoured


def test_heuristic_port_scan():
    det = HeuristicDetector(load_config()["detection"])
    threats = []
    for port in range(1, 40):
        threats += det.observe(_pkt("185.220.101.5", "10.0.0.2", port))
    kinds = {t.kind for t in threats}
    assert "port_scan" in kinds


def test_heuristic_syn_flood():
    det = HeuristicDetector(load_config()["detection"])
    threats = []
    for i in range(80):
        threats += det.observe(_pkt("203.0.113.9", "10.0.0.2", 80, flags="S"))
    assert any(t.kind == "syn_flood" for t in threats)


def test_anomaly_trains_and_flags():
    cfg = load_config()["detection"]
    cfg = dict(cfg, warmup_flows=30)
    det = AnomalyDetector(cfg)
    ft = FlowTable()
    # feed 30 uniform "normal" flows to train
    for i in range(30):
        f = ft.add(_pkt("10.0.0.5", "10.0.0.2", 443, flags="PA", length=200))
        f.key = ("10.0.0.5", "10.0.0.2", "tcp", 40000 + i, 443)  # distinct flows
        det.score_flow(f)
    assert det.trained
    # a wildly different flow (huge, weird port) should be flagged
    weird = ft.add(_pkt("10.0.0.9", "9.9.9.9", 4444, flags="PA", length=65000))
    weird.packets, weird.bytes = 5000, 60_000_000
    weird.sizes = [1500] * 50
    t = det.score_flow(weird)
    assert t is not None and t.kind == "anomaly"


def test_config_defaults_without_yaml():
    cfg = load_config("/nonexistent/path.yml")
    assert cfg["detection"]["scan_threshold"] > 0
    assert cfg["dashboard"]["port"] == 8787


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        fn()
        print("  ok:", fn.__name__)
        passed += 1
    print(f"\n{passed}/{len(fns)} tests passed")
