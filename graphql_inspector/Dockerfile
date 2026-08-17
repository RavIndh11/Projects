FROM python:3.11-slim

# Create a non-root user for security
RUN groupadd -r appuser && useradd -r -g appuser -u 10001 appuser

# Set working directory
WORKDIR /app

# Install dependencies first (caching layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY ./app /app/app

# Change ownership to non-root user
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8000

# Healthcheck using standard python urllib (since slim image might lack curl)
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')" || exit 1

# Run the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
