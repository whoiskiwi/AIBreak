"""Hop-1 internal monitor (downstream consumer that turns the config-root
poisoning into secret disclosure).

Polls the panel's public /config, takes config["root"] as its asset-CDN base,
and fetches <root>/asset-feed attaching the internal token headers. This is
the synthetic-but-declared deployment glue (see PLAN.md §3: scenario is
honestly labelled synthetic; the vulnerability is real).
"""
import json
import os
import time
import urllib.request

PANEL = os.environ.get("PANEL_URL", "http://panel:7860")
INTERVAL = float(os.environ.get("POLL_INTERVAL", "1"))
TOKEN = os.environ.get("HOP1_TOKEN", "")
MODEL_SERVER = os.environ.get("MODEL_SERVER", "http://model-a:8090")


def config_root():
    with urllib.request.urlopen(PANEL + "/config", timeout=3) as r:
        return json.loads(r.read()).get("root", "")


def fetch_feed(root):
    url = root.rstrip("/") + "/asset-feed"
    req = urllib.request.Request(
        url,
        headers={"X-Internal-Token": TOKEN, "X-Model-Server": MODEL_SERVER},
    )
    with urllib.request.urlopen(req, timeout=3) as r:
        return json.loads(r.read())


def main():
    while True:
        try:
            root = config_root()
            fetch_feed(root)
        except Exception:
            pass
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
