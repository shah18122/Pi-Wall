"""Pi-Wall command-line entry point.

  pi-wall run                 # simulate traffic + dashboard (runs anywhere)
  pi-wall run --live --iface eth0   # capture real traffic (needs sudo)
  pi-wall run --enforce             # actually drop blocked IPs (Linux+root)
  pi-wall run --no-dashboard --seconds 30   # headless, console summary

On launch Pi-Wall immediately starts tracking ALL traffic on the source.
"""
import argparse
import sys
import time

from .config import load_config, load_rules
from .engine import PiWallEngine


def _print_banner(engine, live, dashboard_url):
    print("=" * 58)
    print("  🛡️  Pi-Wall — AI-augmented Raspberry Pi firewall")
    print("=" * 58)
    print(f"  source     : {'live capture' if live else 'traffic simulator'}")
    print(f"  enforcement: {engine.firewall.mode}")
    print(f"  AI advisor : {'Claude API' if engine.advisor._llm() else 'template (set ANTHROPIC_API_KEY for LLM)'}")
    if dashboard_url:
        print(f"  dashboard  : {dashboard_url}")
    print("  tracking all traffic — Ctrl-C to stop")
    print("=" * 58)


def _console_summary(engine):
    s = engine.snapshot()
    print(f"\n[{s['uptime']:.0f}s] packets={s['packets']} "
          f"allow={s['allowed']} deny={s['denied']} "
          f"flows={s['active_flows']} threats={len(s['threats'])} "
          f"blocked={len(s['blocked'])} "
          f"AI={'trained' if s['anomaly_trained'] else 'learning'}")
    for t in s["threats"][:3]:
        line = f"   🚨 {t['severity']:<8} {t['kind']:<11} {t['src']:<16} {t['detail']}"
        print(line)
        if t.get("advice"):
            print(f"      🤖 {t['advice']['summary']}")


def run(args):
    cfg = load_config(args.config)
    rules = load_rules(args.rules)
    if args.enforce:
        cfg["enforcement"]["mode"] = "enforce"

    engine = PiWallEngine(cfg, rules, simulate=not args.live, iface=args.iface)

    app = None
    if not args.no_dashboard:
        from .dashboard import create_app
        app = create_app(engine)

    host, port = cfg["dashboard"]["host"], args.port or cfg["dashboard"]["port"]
    url = f"http://{host}:{port}" if app else None
    _print_banner(engine, args.live, url)
    engine.start()

    try:
        if app:
            # Flask serves in the main thread; engine runs in its own thread.
            app.run(host=host, port=port, debug=False, use_reloader=False)
        else:
            deadline = time.time() + args.seconds if args.seconds else None
            while deadline is None or time.time() < deadline:
                time.sleep(3)
                _console_summary(engine)
    except KeyboardInterrupt:
        pass
    finally:
        engine.stop()
        _console_summary(engine)
        print("\nPi-Wall stopped.")


def main(argv=None):
    p = argparse.ArgumentParser(prog="pi-wall", description="AI firewall for Raspberry Pi")
    sub = p.add_subparsers(dest="cmd")
    r = sub.add_parser("run", help="start the firewall")
    r.add_argument("--live", action="store_true", help="capture real traffic (needs root)")
    r.add_argument("--iface", help="interface for live capture")
    r.add_argument("--enforce", action="store_true", help="actually drop blocked IPs")
    r.add_argument("--no-dashboard", action="store_true", help="headless console mode")
    r.add_argument("--seconds", type=int, default=0, help="run for N seconds then exit (headless)")
    r.add_argument("--port", type=int, help="dashboard port")
    r.add_argument("--config", help="path to piwall.yml")
    r.add_argument("--rules", help="path to rules.yml")

    args = p.parse_args(argv)
    if args.cmd == "run":
        run(args)
    else:
        p.print_help()
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
