# syntax=docker/dockerfile:1

FROM python:3.11-slim

WORKDIR /app

# system deps for scapy / pyshark may be added later (tcpdump, tshark)
# keep minimal for first build
RUN apt-get update && apt-get install -y --no-install-recommends \
    net-tools iproute2 tshark tcpdump \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# copy code
COPY src ./src

# create default artifact dir (model + feature_order live here at runtime)
RUN mkdir -p /app/model_artifacts

ENV THREATSCOPE_ARTIFACTS=/app/model_artifacts
ENV THREATSCOPE_DB=/app/threatscope_alerts.db

EXPOSE 8000

CMD ["python", "-m", "src.api.main"]
