FROM python:3.12-slim

WORKDIR /app

# Install uv
RUN pip install --no-cache-dir uv

# Copy dependency files first for better caching
COPY pyproject.toml uv.lock ./

# Install dependencies
RUN uv sync --frozen --no-dev

# Copy application code
COPY main.py ./

# Run the server
CMD ["uv", "run", "fastapi", "run", "--host", "0.0.0.0", "--port", "8000"]
