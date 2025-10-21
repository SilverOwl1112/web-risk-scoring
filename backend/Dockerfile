# Use a stable Python base image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies (for psycopg2 & pandas)
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    python3-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy app files
COPY ./app /app/app
COPY ./../ml/models /app/ml/models
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose backend port
EXPOSE 8000

# Run FastAPI with Uvicorn
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
