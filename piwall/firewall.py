"""Rule-based firewall engine + safe enforcement.

Evaluates every packet against ordered rules (first match wins) and against a
dynamic blocklist that the AI detector populates. Enforcement is dry-run by
default; in `enforce` mode on Linux+root it installs nftables drop rules.
Loopback / gateway / admin hosts are never blocked.
"""
import ipaddress
import subprocess
import time


class Rule:
    def __init__(self, action, proto, src, dport, note=""):
        self.action = action
        self.proto = proto
        self.net = ipaddress.ip_network(src, strict=False)
        self.dport = int(dport)
        self.note = note

    def matches(self, pkt):
        if self.proto not in (pkt["proto"], "any"):
            return False
        if self.dport not in (pkt["dport"], 0):
            return False
        try:
            return ipaddress.ip_address(pkt["src"]) in self.net
        except ValueError:
            return False


class Firewall:
    def __init__(self, rules_cfg, mode="dry-run"):
        self.default = rules_cfg.get("default_policy", "allow")
        self.rules = [Rule(**r) for r in rules_cfg.get("rules", [])]
        self.never_block = set(rules_cfg.get("never_block", ["127.0.0.1"]))
        self.mode = mode
        self.blocked = {}     # ip -> {reason, ts}
        self.stats = {"allow": 0, "deny": 0, "blocked_hits": 0}

    def evaluate(self, pkt):
        """Return (action, reason) for a packet."""
        if pkt["src"] in self.blocked:
            self.stats["blocked_hits"] += 1
            self.stats["deny"] += 1
            return "deny", "source is on the AI blocklist"
        for rule in self.rules:
            if rule.matches(pkt):
                self.stats[rule.action] += 1
                return rule.action, rule.note or f"rule:{rule.action}"
        self.stats[self.default] += 1
        return self.default, "default policy"

    def block(self, ip, reason):
        """Add an IP to the blocklist (and enforce, if configured)."""
        if ip in self.never_block or ip in self.blocked:
            return False
        self.blocked[ip] = {"reason": reason, "ts": time.time()}
        if self.mode == "enforce":
            self._enforce(ip)
        return True

    def _enforce(self, ip):
        """Install an nftables drop rule (Linux + root only). Best-effort."""
        try:
            subprocess.run(
                ["nft", "add", "rule", "inet", "piwall", "input",
                 "ip", "saddr", ip, "drop"],
                check=False, capture_output=True, timeout=5)
        except (FileNotFoundError, subprocess.SubprocessError):
            pass  # not on Linux / nft absent — stays a logical block
