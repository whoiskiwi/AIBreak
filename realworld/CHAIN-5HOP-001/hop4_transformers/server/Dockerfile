# CVE-2024-11392 — REAL vulnerable software (hop 4 of CHAIN-5HOP-001).
# ARG TF_VERSION selects the installed transformers release:
#   4.47.1  → vulnerable wheel (ships mobilevitv2/convert_mlcvnets_to_pytorch.py with torch.load)
#   4.48.0  → patched wheel   (conversion scripts removed from release wheels)
ARG TF_VERSION=4.47.1
FROM python:3.11-slim

ARG TF_VERSION
ENV TF_VERSION=${TF_VERSION}

RUN apt-get update -qq && apt-get install -y -qq curl > /dev/null && rm -rf /var/lib/apt/lists/*

# The REAL package at the REAL affected version. No simulated vulnerability:
# the bug ships inside this wheel.
RUN pip install --no-cache-dir transformers==${TF_VERSION} flask requests

# torch pinned < 2.6: PyTorch 2.6 flipped torch.load to weights_only=True by
# default, which would mask the deserialization bug in the transformers wheel.
RUN pip install --no-cache-dir "torch>=2.0,<2.6" "torchvision<0.21" "timm" "pillow" "safetensors" "pyyaml"

# Hop-4 loot: the model-conversion service C's credentials for the keras
# preprocessing service (hop 5's ticket). Value must match hop5's gate
# (compose passes KERAS_SESSION_TOKEN at build/run time; both default here).
ARG KERAS_SESSION_TOKEN=keras-preprocess-login-default-dev
RUN mkdir -p /etc/run-secrets && \
    echo "keras-preprocess-login:${KERAS_SESSION_TOKEN}" > /etc/run-secrets/keras_session && \
    chmod 600 /etc/run-secrets/keras_session

WORKDIR /app
COPY service.py .

EXPOSE 8080
CMD ["python3", "service.py"]
