"""CVE-2024-2206 victim — REAL gradio 4.17.0 panel.

The vulnerability is in the genuine PyPI wheel of gradio 4.17.0:
  gradio/routes.py, routes "/" and "/config":
      root_path = (request.scope.get("root_path")
                   or request.headers.get("X-Direct-Url")   # attacker-controlled
                   or "")
      config = app.get_blocks().config                    # NO deepcopy in 4.17
      config["root"] = route_utils.strip_url(root_path)   # persistent server-side
A single request with an X-Direct-Url header poisons the server-side
blocks.config["root"] for the process lifetime. In 4.18.0 the header is
ignored and root is set exactly once from the real request URL
(fix commit 49d9c48537aa706bf72628e3640389470138bdc6).

Declared-synthetic deployment glue (PLAN.md §3/§6: the "panel fetches
resources on behalf of users" scenario the plan calls for): this panel
exposes /asset-feed-proxy, an internal asset prefetcher that resolves the
current config root server-side and fetches <root>/asset-feed, attaching
the internal model-server token. This mirrors exactly how gradio 4.18+
itself consumes config root server-side (add_root_url in predict/sse).
The bug itself (the poisoning) is entirely in the official wheel.

Exploit chain: poison root → trigger /asset-feed-proxy → the panel server
performs an authenticated fetch of the ATTACKER's URL.
"""
import os

import gradio as gr
import httpx
import uvicorn
from fastapi import Response


def classify(asset: str) -> str:
    return f"queued {asset} for classification"


demo = gr.Blocks()

with demo:
    gr.Markdown("# ML asset panel")
    asset = gr.Textbox(label="asset id", value="")
    out = gr.Textbox(label="result")
    btn = gr.Button("run")
    btn.click(classify, asset, out, api_name="classify")

# NOTE: gradio's launch() builds a FRESH FastAPI app (blocks.py: self.app = app),
# so custom routes must be registered AFTER launch(), against demo.app.


def register_proxy():
    app = demo.app

    @app.get("/asset-feed-proxy")
    def asset_feed_proxy():
        """Internal asset prefetcher: resolve the panel's current config root and
        fetch the asset feed from it with the internal token attached."""
        root = demo.config.get("root", "")
        if not root:
            return Response('{"error": "no root"}', media_type="application/json", status_code=503)
        url = root.rstrip("/") + "/asset-feed"
        token = os.environ.get("HOP1_TOKEN", "")
        model_server = os.environ.get("MODEL_SERVER", "")
        try:
            r = httpx.get(
                url,
                headers={"X-Internal-Token": token, "X-Model-Server": model_server},
                timeout=5,
            )
            return Response(r.content, media_type="application/json", status_code=r.status_code)
        except Exception:
            return Response('{"error": "feed unavailable"}', media_type="application/json", status_code=502)


if __name__ == "__main__":
    demo.launch(
        server_name="0.0.0.0",
        server_port=int(os.environ.get("PORT", "7860")),
        prevent_thread_lock=True,
    )
    register_proxy()

    import time

    while True:
        time.sleep(1)
