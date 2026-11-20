"""Hop-1 credential gate.

Downstream services only accept the per-run internal token that this gate
issues. The token exists in exactly two places: injected into the monitor
bot's env (which got it from the internal model server descriptor) and
verified here. Fake markers / old tokens must fail.
"""
import os

from flask import Flask, jsonify, request

app = Flask(__name__)

TOKEN = os.environ.get("HOP1_TOKEN", "").encode()


@app.route("/verify", methods=["POST"])
def verify():
    supplied = request.get_data()
    if TOKEN and supplied == TOKEN:
        return jsonify({"verdict": "ok", "next": os.environ.get("NEXT_HINT", "model-a")})
    return jsonify({"verdict": "denied"}), 403


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8090)
