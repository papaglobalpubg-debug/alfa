# CyberScope v7.5 — production Dockerfile
# Builds a single image containing backend + scanner + prebuilt frontend
# served via a lightweight static server. MongoDB runs in a separate
# container via docker-compose.
#
# Build:   docker build -t cyberscope:7.5 .
# Run:     docker compose up -d
FROM python:3.11-slim AS backend-base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    NODE_MAJOR=20 \
    DEBIAN_FRONTEND=noninteractive

# System deps (playwright + curl for healthchecks)
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates gnupg \
        libnss3 libatk-bridge2.0-0 libgtk-3-0 libxkbcommon0 libgbm1 \
        libasound2 libpangocairo-1.0-0 libpango-1.0-0 libcairo2 \
        libatspi2.0-0 libcups2 libxdamage1 libx11-xcb1 libxcomposite1 \
        libxrandr2 fonts-liberation \
        chromium \
    && rm -rf /var/lib/apt/lists/*

# Install Node for frontend build
RUN curl -fsSL https://deb.nodesource.com/setup_$NODE_MAJOR.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && \
    npm install -g yarn serve && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Backend deps
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

# Copy the rest
COPY backend /app/backend
COPY scanner /app/scanner
COPY cyberscope_cli.py /app/cyberscope_cli.py

# Frontend build
COPY frontend/package.json frontend/yarn.lock /app/frontend/
WORKDIR /app/frontend
RUN yarn install --frozen-lockfile 2>/dev/null || yarn install

COPY frontend /app/frontend
# The frontend contacts the backend via REACT_APP_BACKEND_URL — for docker-compose
# we point it at http://localhost:8001 by default; users override with env.
ARG REACT_APP_BACKEND_URL=http://localhost:8001
ENV REACT_APP_BACKEND_URL=$REACT_APP_BACKEND_URL
RUN echo "REACT_APP_BACKEND_URL=$REACT_APP_BACKEND_URL" > /app/frontend/.env && \
    yarn build

WORKDIR /app

# Small process launcher
RUN printf '#!/usr/bin/env bash\nset -e\n(cd /app/backend && python -m uvicorn server:app --host 0.0.0.0 --port 8001 &)\n(cd /app/frontend && serve -s build -l 3000 &)\nwait -n\n' > /entrypoint.sh && chmod +x /entrypoint.sh

# P3 · Run as non-root user to limit blast radius if the app is compromised.
RUN useradd --system --uid 1001 --shell /bin/false --create-home --home-dir /home/cyberscope cyberscope && \
    chown -R cyberscope:cyberscope /app /home/cyberscope
USER cyberscope

EXPOSE 3000 8001

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -fsS http://localhost:8001/api/health || exit 1

ENTRYPOINT ["/entrypoint.sh"]
