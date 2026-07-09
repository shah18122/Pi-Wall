<div align="center">

# 🛡️ Pi-Wall — AI-Augmented Raspberry Pi Firewall

### A compact, low-power firewall for the Raspberry Pi that tracks all traffic in real time and uses next-gen AI — machine-learning anomaly detection plus an LLM threat advisor — to catch and explain attacks.

![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white)
![Raspberry Pi](https://img.shields.io/badge/Raspberry%20Pi-C51A4A?logo=raspberrypi&logoColor=white)
![scikit-learn](https://img.shields.io/badge/AI-scikit--learn-F7931E?logo=scikitlearn&logoColor=white)
![License](https://img.shields.io/badge/License-Open%20Source-green)
![Defensive](https://img.shields.io/badge/Security-Defensive-blue)

</div>

Pi-Wall turns a Raspberry Pi into a smart network sentry. It captures every packet,
enforces a rule-based firewall, and layers **two kinds of AI** on top to spot threats a
static ruleset would miss — then explains each one in plain language and can block the
source automatically. It runs on any machine in a built-in **traffic-simulation mode**, so
you can see it work end-to-end without a Pi or root.

> **Defensive tool.** Pi-Wall monitors, detects and blocks. It does not attack, scan, or
> generate hostile traffic. The bundled traffic simulator produces *synthetic* attack
> patterns purely to demonstrate detection.

---

## ✨ What makes it "next-gen AI"

| Layer | Technique | Catches |
|---|---|---|
| **Heuristic engine** | Deterministic sliding-window rules | Port scans, SYN floods, volumetric DoS — textbook attacks, zero false-negatives |
| **ML anomaly detection** | Unsupervised **IsolationForest** trained on a live baseline of your normal traffic | Novel / zero-day behaviour that matches no rule — e.g. **data exfiltration** to an unusual port |
| **GenAI threat advisor** | **Claude LLM** (Anthropic API) with an offline template fallback | Plain-language explanation + recommended action for every serious alert |

The ML model learns what *your* network looks like during a short warm-up, then flags flows
that deviate from that baseline — so detection adapts to your environment instead of relying
only on fixed signatures.

## 🚀 Quick start (runs on any machine)

```bash
pip install -r requirements.txt

# Simulated traffic + live web dashboard — no root, no Pi needed
python -m piwall.cli run
#  -> open http://127.0.0.1:8787

# Headless console mode for 30 seconds
python -m piwall.cli run --no-dashboard --seconds 30
```

On launch Pi-Wall **immediately begins tracking all traffic** on the chosen source and
starts detecting threats.

### Real capture on a Raspberry Pi

```bash
sudo bash deploy/install-pi.sh                 # deps + systemd service
sudo pi-wall run --live --iface eth0 --enforce # capture real traffic, drop blocked IPs
```

`--enforce` installs `nftables` drop rules for blocked sources (Linux + root); without it,
Pi-Wall runs in **dry-run** mode and only logs what it *would* block.

### Unlock LLM-powered explanations

```bash
export ANTHROPIC_API_KEY=sk-ant-...   # advisor uses Claude; without it, a template is used
```

## 🖥️ Live dashboard

The dashboard shows real-time counters (packets, allowed/denied, active flows, threats,
blocked IPs), a live traffic table with per-packet verdicts, an **AI threat feed** with the
advisor's explanation for each alert, blocked sources, and top talkers.

## 🧠 How it works

```
 packets ─▶ Firewall (rules + AI blocklist) ─▶ allow / deny
    │
    ├─▶ Flow tracker ──▶ IsolationForest anomaly model ─┐
    └─▶ Heuristic detector (scan / flood / DoS) ────────┤
                                                        ▼
                                          Threat scoring & auto-block
                                                        │
                                                        ▼
                                     GenAI advisor: explain + recommend
```

- **`piwall/capture.py`** — live scapy capture + synthetic traffic simulator
- **`piwall/flows.py`** — 5-tuple flow tracking + feature extraction
- **`piwall/detector.py`** — heuristic rules + IsolationForest anomaly model
- **`piwall/firewall.py`** — rule engine, dynamic blocklist, nftables enforcement
- **`piwall/ai_advisor.py`** — Claude/LLM threat explanations (template fallback)
- **`piwall/engine.py`** — orchestrates capture → detection → response
- **`piwall/dashboard.py`** — Flask real-time dashboard + REST API

## ✅ Verified behaviour

Against the built-in attack simulation, Pi-Wall reliably:

- detects **port scans**, **SYN floods** and **volumetric floods** (heuristics),
- trains its anomaly model on normal traffic and then **isolates a data-exfiltration flow**
  (bulk transfer to port 4444) with no false positives on normal web/DNS traffic,
- **auto-blocks** the offending sources (port scanner, SYN flooder, exfil host),
- never blocks loopback / gateway / admin hosts,
- produces an analyst-style explanation for each serious threat.

Run the tests:

```bash
python tests/test_core.py
```

## ⚙️ Configuration

- `config/rules.yml` — firewall rules (first-match-wins), default policy, never-block hosts
- `config/piwall.yml` — detection thresholds, warm-up size, enforcement mode, AI settings

## 🔍 Keywords

`raspberry-pi firewall network-security ai anomaly-detection machine-learning isolation-forest
intrusion-detection ids ips scapy packet-capture nftables llm claude defensive-security
port-scan-detection ddos-detection python`
