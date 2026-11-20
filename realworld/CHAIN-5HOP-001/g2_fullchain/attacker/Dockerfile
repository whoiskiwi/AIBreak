# Chain attacker image: hop adapters need lerobot 0.5.1 proto modules (hop 2)
# plus generic tooling.
FROM python:3.12-slim
RUN apt-get update -qq && apt-get install -y -qq gcc g++ > /dev/null && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir "lerobot[grpcio-dep]==0.5.1"
WORKDIR /chain
CMD ["sleep", "infinity"]
