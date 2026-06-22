FROM python:3.11-slim

WORKDIR /app

# Install git (required for cloning repositories)
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency metadata and install first for layer caching
COPY pyproject.toml ./
RUN pip install --no-cache-dir -e "."

# Ensure imports like `src.*` work from the project root
ENV PYTHONPATH=/app

# Copy application code
COPY . .

EXPOSE 8080

CMD ["python", "src/main.py", "--serve"]
