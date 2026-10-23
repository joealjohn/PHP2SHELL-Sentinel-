FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY packages/shared packages/shared
COPY packages/vulnerability-db packages/vulnerability-db
COPY packages/scanner packages/scanner
COPY apps/api/requirements.txt apps/api/requirements.txt
RUN pip install \
    ./packages/shared \
    ./packages/vulnerability-db \
    ./packages/scanner \
    -r apps/api/requirements.txt

ENV SENTINEL_VULNDB_DATA=/data
COPY packages/vulnerability-db/data /data

COPY apps/api apps/api
RUN pip install -e ./apps/api 2>/dev/null || true

WORKDIR /app/apps/api
EXPOSE 8000
ENV PYTHONPATH=/app/apps/api

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD python -c "import urllib.request,sys; \
r=urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=4); \
sys.exit(0 if r.status==200 else 1)"

CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 1"]
