"""GenAI threat advisor — natural-language explanations & recommended actions.

When a serious threat is detected, Pi-Wall asks an LLM to explain it in plain
language and recommend a response — the kind of analyst summary a SOC would
write. It uses the Anthropic API (Claude) when ANTHROPIC_API_KEY is set, and
falls back to a built-in template so the firewall stays fully functional
offline.

Deps (optional): pip install anthropic
"""
import os
import time


TEMPLATES = {
    "port_scan": ("A horizontal port scan means a single host is probing many "
                  "ports to map open services — usually reconnaissance before "
                  "an attack.",
                  "Block the source and confirm no admin service is exposed."),
    "syn_flood": ("A SYN flood sends many half-open TCP connections to exhaust "
                  "the server's connection table — a denial-of-service attack.",
                  "Block the source, enable SYN cookies, and rate-limit new "
                  "connections."),
    "volumetric": ("A volumetric flood overwhelms the link with sheer packet "
                   "volume to deny service to legitimate users.",
                   "Block the source and consider upstream rate-limiting."),
    "anomaly": ("This flow doesn't match learned normal behaviour — it may be "
                "data exfiltration, C2 traffic, or a new attack pattern.",
                "Investigate the destination and source; block if unexpected."),
}


class AIAdvisor:
    def __init__(self, cfg):
        self.enabled = cfg.get("enabled", True)
        self.model = cfg.get("model", "claude-opus-4-8")
        self.max_per_min = cfg.get("max_explanations_per_min", 8)
        self._times = []
        self._client = None
        self._llm_ready = None

    def _rate_ok(self):
        now = time.time()
        self._times = [t for t in self._times if now - t < 60]
        if len(self._times) >= self.max_per_min:
            return False
        self._times.append(now)
        return True

    def _llm(self):
        if self._llm_ready is None:
            self._llm_ready = False
            if os.environ.get("ANTHROPIC_API_KEY"):
                try:
                    import anthropic
                    self._client = anthropic.Anthropic()
                    self._llm_ready = True
                except Exception:  # noqa: BLE001 - SDK missing / bad key
                    self._llm_ready = False
        return self._llm_ready

    def explain(self, threat):
        """Return {summary, action, source: 'llm'|'template'}."""
        if not self.enabled or not self._rate_ok():
            return None

        if self._llm():
            try:
                msg = self._client.messages.create(
                    model=self.model,
                    max_tokens=300,
                    system=("You are a network security analyst embedded in a "
                            "Raspberry Pi firewall. Given a detected threat, "
                            "reply in 2 sentences: what it is and the single "
                            "most important defensive action. Be concise and "
                            "concrete."),
                    messages=[{"role": "user", "content": (
                        f"Threat type: {threat.kind}\n"
                        f"Source IP: {threat.src}\n"
                        f"Severity: {threat.severity}\n"
                        f"Detail: {threat.detail}")}],
                )
                text = "".join(b.text for b in msg.content if b.type == "text")
                return {"summary": text.strip(), "action": "", "source": "llm"}
            except Exception as e:  # noqa: BLE001 - degrade to template on any API error
                pass

        summary, action = TEMPLATES.get(
            threat.kind, ("Unrecognised suspicious activity.",
                          "Investigate and block if unexpected."))
        return {"summary": summary, "action": action, "source": "template"}
