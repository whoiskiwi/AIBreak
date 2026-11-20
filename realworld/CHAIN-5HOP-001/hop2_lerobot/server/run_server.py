"""Start the REAL lerobot PolicyServer gRPC service.

The vulnerability ships in the official wheel (0.5.1): the gRPC handler
SendPolicyInstructions calls pickle.loads(request.data) on unauthenticated
insecure-channel bytes. This script only starts the real server via the
library's own serve() entry point.
"""
from lerobot.async_inference.configs import PolicyServerConfig
from lerobot.async_inference.policy_server import PolicyServer, serve  # noqa: F401


def main():
    import sys

    sys.argv = ["policy_server"]
    # draccus CLI: --host/--port
    sys.argv += ["--host=0.0.0.0", "--port=8080"]
    serve()


if __name__ == "__main__":
    main()
