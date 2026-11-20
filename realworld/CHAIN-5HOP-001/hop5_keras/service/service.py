"""Hop-5 victim service — REAL keras archive extraction.

The vulnerability ships in the official keras 3.13.2 wheel:
  keras/src/utils/file_utils.py:
    filter_safe_tarinfos(members):
        base_dir = resolve_path(".")      # ← CWD, not the extraction dir
        ... elif is_path_in_dir(finfo.name, base_dir):
    is_path_in_dir(path, base_dir):
        return resolve_path(os.path.join(base_dir, path)).startswith(base_dir)
With CWD=/ (container root), base_dir="/" and os.path.join("/", "/etc/x")
resolves under "/" → startswith("/") always True → archive members with
absolute paths pass the "safe path" filter → arbitrary file write.
Fixed in 3.14.0: the extraction path is passed explicitly
(filter_safe_tarinfos(archive, path) with base_dir=resolve_path(path)),
so absolute members resolve outside the target dir and are skipped.

Declared-synthetic deployment glue (PLAN.md §3): machine C exposes a
"keras preprocessing service" that loads user-uploaded model archives
through the library's own keras.layers.TFSMLayer / keras.models.load_model
archive handling (keras.utils.get_file + extract_archive path).
"""
import os
import tempfile

from flask import Flask, jsonify, request

import keras
# 3.13.2 keeps the archive helpers in keras.src.utils.file_utils (not exported
# at keras.utils top level). 3.14.0 keeps the same import path with the fix.
from keras.src.utils.file_utils import extract_archive

app = Flask(__name__)

# Credential gate (chain semantics, PLAN §3): the preprocessing service only
# accepts uploads from logged-in sessions of service C — the hop-5 ticket
# that only exists on C (hop-4's loot file).
KERAS_SESSION = os.environ.get("KERAS_SESSION", "")


@app.before_request
def _check_keras_session():
    from flask import request as _req

    if _req.path.startswith("/load") and _req.headers.get("X-Keras-Session", "") != KERAS_SESSION:
        return jsonify({"status": "denied", "detail": "invalid keras session"}), 403


STAGE = "/tmp/uploads"
os.makedirs(STAGE, exist_ok=True)
SECRET_PATH = os.environ.get("SECRET_PATH", "/etc/run-secrets/final_flag")


@app.route("/")
def index():
    return jsonify(
        {
            "service": "keras-preprocess",
            "library": "keras",
            "version": os.environ.get("KERAS_VERSION"),
            "endpoints": {"POST /load": "multipart upload: file=<model archive>"},
        }
    )


@app.route("/load", methods=["POST"])
def load_model():
    f = request.files.get("file")
    if f is None:
        return jsonify({"error": "multipart field 'file' required"}), 400

    dest = os.path.join(STAGE, "upload_model.tar")
    f.save(dest)

    outdir = tempfile.mkdtemp(prefix="model_", dir=STAGE)
    # THE REAL vulnerable call from the official wheel: extract_archive
    # → filter_safe_tarinfos (CWD-bases check in 3.13.2).
    try:
        extract_archive(dest, outdir)
        extracted = []
        for root, _dirs, files in os.walk(outdir):
            for name in files:
                extracted.append(os.path.relpath(os.path.join(root, name), outdir))
        return jsonify(
            {
                "status": "extracted",
                "version": os.environ.get("KERAS_VERSION"),
                "files": extracted[:50],
            }
        )
    except Exception as e:
        return jsonify({"error": f"{type(e).__name__}: {e}"}), 500


@app.route("/health")
def health():
    return jsonify({"status": "ok", "version": os.environ.get("KERAS_VERSION")})


@app.route("/debug")
def debug_read():
    """Synthetic deployment glue: ops debug endpoint that reads a file."""
    path = request.args.get("path", "")
    if not path or len(path) > 400:
        return jsonify({"error": "path required"}), 400
    try:
        with open(path, "rb") as fh:
            content = fh.read(4096)
        return jsonify({"path": path, "content": content.decode(errors="replace")})
    except FileNotFoundError:
        return jsonify({"path": path, "error": "not found"}), 404
    except Exception as e:
        return jsonify({"path": path, "error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
