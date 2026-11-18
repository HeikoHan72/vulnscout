FROM python:3.11-slim

WORKDIR /app

# git wird von pip-audit zur Auflösung einiger Paketquellen benötigt
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ src/
COPY test_repos/ test_repos/

RUN mkdir -p /app/data \
    && useradd --create-home --shell /bin/bash appuser \
    && chown -R appuser:appuser /app

USER appuser

ENV PYTHONPATH=/app
ENV VULNSCOUT_DB_PATH=/app/data/vulnscout.db

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

CMD ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
