# CVE-2026-25874 — REAL vulnerable software.
# ARG LEROBOT_VERSION selects the installed release:
#   0.5.1  → vulnerable wheel (async_inference/policy_server.py pickle.loads(request.data))
#   0.7.0  → patched wheel   (async_inference gRPC service removed; remote_inference
#            zenoh transport + msgpack codec, no server-side pickle.loads of peer bytes)
ARG LEROBOT_VERSION=0.5.1
FROM python:3.12-slim
ARG LEROBOT_VERSION
ENV LEROBOT_VERSION=${LEROBOT_VERSION}

# evdev (lerobot dep) builds from source: needs gcc.
RUN apt-get update -qq && apt-get install -y -qq gcc g++ git > /dev/null && rm -rf /var/lib/apt/lists/*
# cpu-index torch first (lerobot 0.7.0 core-deps torch; avoids pulling CUDA wheels)
RUN if [ "$LEROBOT_VERSION" != "0.5.1" ]; then pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu "torch>=2.7,<2.16.0" "torchvision>=0.22.0,<0.30.0"; fi
RUN pip install --no-cache-dir "lerobot[grpcio-dep]==${LEROBOT_VERSION}"

# 0.7.0 replaced grpc with zenoh+msgpack for policy serving.
RUN if [ "$LEROBOT_VERSION" != "0.5.1" ]; then pip install --no-cache-dir "eclipse-zenoh>=1.9.0,<1.11.0" "msgpack>=1.1.0,<2.0.0"; fi

WORKDIR /app
COPY run_server.py run_server_070.py ./

# Hop-2 loot: model server A holds the SSH key that is the ONLY ticket to hop-3.
# Per-run random value would be injected at runtime; a fixed dev value keeps the
# image build deterministic for G1 verification. checker treats it as opaque.
RUN mkdir -p /loot && echo "-----BEGIN OPENSSH PRIVATE KEY-----" > /loot/id_rsa && \
    echo "HOP2-SSH-KEY-$(cat /proc/sys/kernel/random/uuid | tr -d '-')" >> /loot/id_rsa && \
    echo "-----END OPENSSH PRIVATE KEY-----" >> /loot/id_rsa && chmod 600 /loot/id_rsa

EXPOSE 8080 7447
CMD ["sh", "-c", "if [ \"$LEROBOT_VERSION\" = \"0.5.1\" ]; then python run_server.py; else python run_server_070.py; fi"]
