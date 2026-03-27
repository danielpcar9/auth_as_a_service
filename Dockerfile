# Start from the official Python 3.12 image
FROM python:3.12-slim

# Install system dependencies needed for compiling psycopg2 and other packages
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Install uv (fast Python package installer and resolver)
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:${PATH}"

# Copy the dependency files
# We use uv sync to install dependencies based on uv.lock
COPY pyproject.toml uv.lock ./

# Install dependencies (system-wide inside the container)
RUN uv sync --frozen

# Copy the rest of the application
COPY . .

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Expose the API port
EXPOSE 8000

# Start the application using uv run to leverage the virtual environment created by uv
CMD ["uv", "run", "fastapi", "run", "src/main.py", "--host", "0.0.0.0", "--port", "8000"]
