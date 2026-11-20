# Attacker container for hop 4 — CLEAN tooling + reference exploit.
FROM python:3.11-slim

RUN apt-get update -qq && apt-get install -y -qq curl > /dev/null && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir flask requests

WORKDIR /app
COPY reference_exploit.py .

CMD ["sleep", "infinity"]
