# Use Python 3.10 slim base image for smaller footprint
FROM harbor.app.clemson.edu/dockerhub-proxy/python:3.10-slim

# Set working directory
WORKDIR /app

# Install system dependencies (for pyvmomi and build tools)
RUN export http_proxy=http://proxy.app.clemson.edu:8080 && apt-get update && apt-get install -y \
    gcc \
    libssl-dev \
    git \ 
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file
COPY requirements.txt .

# Install Python dependencies
RUN export https_proxy=http://proxy.app.clemson.edu:8080 &&  pip install --no-cache-dir -r requirements.txt

# Copy the script and ensure it's executable
COPY vmware-sync.py .
RUN chmod +x vmware-sync.py

# Create directory for regex files
RUN mkdir regex

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Command to run the script
CMD ["python3", "vmware-sync.py"]
