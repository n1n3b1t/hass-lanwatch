# syntax=docker/dockerfile:1
FROM python:3.11-alpine AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# System dependencies: libpcap for scapy ARP operations
RUN apk add --no-cache libpcap

WORKDIR /app

# Install python dependencies first to leverage layer caching
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy application code
COPY lanwatch/lanwatch.py /app/lanwatch.py

# Default command
CMD ["python", "/app/lanwatch.py"] 