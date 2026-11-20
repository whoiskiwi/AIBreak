# CVE-2024-2206 panel — REAL vulnerable software.
# ARG GRADIO_VERSION selects the installed release:
#   4.17.0  → vulnerable wheel (/ and /config trust X-Direct-Url, no deepcopy)
#   4.18.0  → patched wheel   (header ignored, root set once, deepcopy)
ARG GRADIO_VERSION=4.17.0
FROM python:3.11-slim
ARG GRADIO_VERSION
ENV GRADIO_VERSION=${GRADIO_VERSION}

# 2024-era dependency pins (huggingface_hub 0.25 removed HfFolder which 4.17 imports).
RUN pip install --no-cache-dir \
    "gradio==${GRADIO_VERSION}" \
    "huggingface_hub==0.20.3" \
    "pydantic==2.6.3" \
    "fastapi==0.109.2" \
    "uvicorn==0.27.1" \
    "httpx==0.26.0"

WORKDIR /app
COPY app.py .
EXPOSE 7860
CMD ["python", "app.py"]
