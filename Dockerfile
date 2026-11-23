# Exakt gepinnt per Digest statt floatendem Tag, für reproduzierbare Builds.
# Digest ermittelt mit: docker inspect --format='{{index .RepoDigests 0}}' python:3.11-slim
FROM python@sha256:07d4824036af339fa1b6ef769cc99d9c10a141769538b52b3b597c84f7a7b535

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
