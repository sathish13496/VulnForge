FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    smbclient \
    nfs-common \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Install the package
RUN pip install -e .

# Create data directories
RUN mkdir -p data/nvd data/rules reports

# Expose web UI port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=5s \
    CMD python -c "import requests; requests.get('http://localhost:5000/api/scan/status')" || exit 1

# Run the web server
CMD ["linarmor", "--web", "--host", "0.0.0.0", "--port", "5000"]
