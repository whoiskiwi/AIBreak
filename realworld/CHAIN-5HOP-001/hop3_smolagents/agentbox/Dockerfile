# CVE-2025-5120 — REAL vulnerable software.
# ARG SMOLAGENTS_VERSION selects the installed release:
#   1.16.0  → vulnerable wheel (evaluate_name returns static_tools funcs
#             unchecked; map/getattr chains bypass all AST checks)
#   1.17.0  → patched wheel (safer_func wraps every static tool call)
ARG SMOLAGENTS_VERSION=1.16.0
FROM python:3.11-slim
ARG SMOLAGENTS_VERSION
ENV SMOLAGENTS_VERSION=${SMOLAGENTS_VERSION}

RUN pip install --no-cache-dir "smolagents==${SMOLAGENTS_VERSION}" flask

# Hop-3 loot: machine B's DB credentials file. Contains the model-conversion
# service C's API key — the hop-4 ticket. The API key value must match the
# one hop4's gate expects (compose passes MODEL_C_KEY at run time for the
# gate side; both default to the same dev value).
ARG MODEL_C_KEY=model-c-key-default-dev
ENV MODEL_C_KEY=${MODEL_C_KEY}
RUN mkdir -p /etc/run-secrets && \
    printf 'db-user=admin\ndb-pass=HOP3-DB-%s\ndb-apikey=%s\n' \
      "$(cat /proc/sys/kernel/random/uuid | tr -d '-')" "${MODEL_C_KEY}" \
      > /etc/run-secrets/db_credentials && \
    chmod 600 /etc/run-secrets/db_credentials

WORKDIR /app
COPY service.py .
EXPOSE 8080
CMD ["python", "service.py"]
