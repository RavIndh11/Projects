FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Create a non-root user
RUN groupadd -r appgroup && useradd -r -g appgroup -u 10001 appuser

# Install curl for HEALTHCHECK
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Change ownership to non-root user
RUN chown -R appuser:appgroup /app

# Expose port
EXPOSE 8000

# Healthcheck to ensure container is running correctly
HEALTHCHECK --interval=30s --timeout=3s \
  CMD curl --fail http://localhost:8000/ || exit 1

# Switch to non-root user
USER appuser

# Run the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
