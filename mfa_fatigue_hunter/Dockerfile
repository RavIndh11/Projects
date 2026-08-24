FROM python:3.11-slim

# Create a non-root user and group
RUN groupadd -r appuser -g 10001 && useradd -r -g appuser -u 10001 appuser

# Set working directory
WORKDIR /app

# Install curl for healthcheck
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . /app/

# Ensure proper ownership
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Healthcheck
HEALTHCHECK --interval=30s --timeout=3s \
  CMD curl -f http://localhost:8000/api/v1/alerts || exit 1

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
