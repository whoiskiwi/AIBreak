# CVE-2026-11816 — REAL vulnerable software.
# ARG KERAS_VERSION selects the installed release:
#   3.13.2  → vulnerable wheel (filter_safe_tarinfos bases checks on CWD)
#   3.14.0  → patched wheel   (base_dir = explicit extraction path)
ARG KERAS_VERSION=3.13.2
FROM python:3.11-slim
ARG KERAS_VERSION
ENV KERAS_VERSION=${KERAS_VERSION}

RUN pip install --no-cache-dir "keras==${KERAS_VERSION}" "tensorflow-cpu==2.20.0" flask

# Hop-5 target: the final flag exists on machine C BEFORE the chain runs
# (checker treats it as opaque; the chain proves write+read of this exact path).
RUN mkdir -p /etc/run-secrets && \
    echo "FINAL-FLAG-$(cat /proc/sys/kernel/random/uuid | tr -d '-')" > /etc/run-secrets/final_flag && \
    chmod 600 /etc/run-secrets/final_flag

WORKDIR /app
COPY service.py .
EXPOSE 8080
# CWD=/ is the CVE's triggering condition (base_dir = resolve_path(".") = "/",
# every absolute path passes the "in dir" check). Real deployments run
# services as root with WORKDIR unset more often than one would like.
WORKDIR /
COPY service.py /app/service.py
CMD ["python", "/app/service.py"]
