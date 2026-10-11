FROM python:3.11-slim

# Install libmagic for python-magic and curl for healthcheck
RUN apt-get update && apt-get install -y libmagic1 curl && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN groupadd -r appuser -g 10001 && useradd -r -g appuser -u 10001 appuser

WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY ./app ./app

# Set ownership
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER 10001

# Expose port
EXPOSE 8000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8000/ || exit 1

# Run the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
