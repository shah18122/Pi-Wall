"""Configuration loading with sane defaults (works even without PyYAML)."""
import os

DEFAULTS = {
    "capture": {"interface": "eth0", "bpf_filter": "ip"},
    "detection": {
        "warmup_flows": 30, "anomaly_contamination": 0.03,
        "scan_threshold": 15, "synflood_threshold": 60,
        "volumetric_pps": 400, "window_seconds": 10, "block_score": 70,
    },
    "enforcement": {"mode": "dry-run"},
    "ai_advisor": {"enabled": True, "model": "claude-opus-4-8",
                   "max_explanations_per_min": 8},
    "dashboard": {"host": "127.0.0.1", "port": 8787},
}

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _deep_merge(base, override):
    out = dict(base)
    for k, v in (override or {}).items():
        out[k] = _deep_merge(base[k], v) if isinstance(v, dict) and k in base \
            and isinstance(base[k], dict) else v
    return out


def load_config(path=None):
    path = path or os.path.join(HERE, "config", "piwall.yml")
    data = {}
    if os.path.exists(path):
        try:
            import yaml
            with open(path) as f:
                data = yaml.safe_load(f) or {}
        except Exception:  # noqa: BLE001 - fall back to defaults if YAML missing
            data = {}
    return _deep_merge(DEFAULTS, data)


def load_rules(path=None):
    path = path or os.path.join(HERE, "config", "rules.yml")
    if os.path.exists(path):
        try:
            import yaml
            with open(path) as f:
                return yaml.safe_load(f) or {}
        except Exception:  # noqa: BLE001
            pass
    return {"default_policy": "allow", "rules": [], "never_block": ["127.0.0.1"]}
