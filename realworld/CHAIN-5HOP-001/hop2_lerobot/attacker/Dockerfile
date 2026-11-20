FROM python:3.12-slim
RUN apt-get update -qq && apt-get install -y -qq gcc g++ > /dev/null && rm -rf /var/lib/apt/lists/*
# grpc path (0.5.1 attack): lerobot 0.5.1 ships the proto modules
RUN pip install --no-cache-dir "lerobot[grpcio-dep]==0.5.1" && \
    pip install --no-cache-dir "eclipse-zenoh>=1.9.0,<1.11.0" msgpack
WORKDIR /app
COPY reference_exploit.py reference_exploit_v2.py ./
CMD ["sleep", "infinity"]
