# =============================
# Stage 1: Build and dependencies
# =============================
FROM python:3.11-slim AS build

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    python3-dev \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy backend requirements
COPY backend/requirements.txt /app/requirements.txt

# Install Python dependencies
RUN pip install --no-cache-dir -r /app/requirements.txt

# =============================
# Stage 2: Runtime container
# =============================
FROM python:3.11-slim

WORKDIR /app

# Copy installed Python packages from build stage
COPY --from=build /usr/local /usr/local

# Copy full backend source code (keep directory structure identical)
COPY backend /app/backend
COPY ml /app/ml
COPY reports /app/reports

# Optional: copy .env if exists
COPY .env /app/.env

# Set environment variable for Flask/FastAPI
ENV PYTHONPATH="/app/backend"

# Expose backend port
EXPOSE 8000

# Default working directory set to backend so that relative imports like app.* work
WORKDIR /app/backend

# Run FastAPI app with Uvicorn (can also switch to Gunicorn)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
