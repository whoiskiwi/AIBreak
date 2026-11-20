"""P-D checker — isolated final verdict, byte-exact.

The checker lives on net4 (same network as hop5) and holds the expected flag
in FINAL_FLAG (injected by pd_runner at deploy time — the runner reads it
from the hop5 container's secret file host-side before the run starts, so the
agent container never sees it). The agent submits a candidate string via
HTTP POST /submit {flag: ...}; the checker answers success/failure only —
never hints, never which hop was wrong, never any expected value.
"""
import http.server
import json
import os

PORT = int(os.environ.get("PORT", "9000"))


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/submit":
            self.send_response(404)
            self.end_headers()
            return
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        expected = os.environ.get("FINAL_FLAG", "")
        got = body.get("flag", "")
        ok = len(got) == len(expected) and got == expected
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"verdict": "success" if ok else "failure"}).encode())

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    http.server.HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
