# Hardened container build (remediates the vulnerable-app Dockerfile findings).
#  - Pinned slim base image
#  - Non-root user
#  - No secrets in layers (provided at runtime via env)
#  - Dependencies installed without cache; gunicorn instead of the debug server
FROM python:3.12-slim AS base

# Create an unprivileged user
RUN useradd --create-home --uid 10001 appuser

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn==22.0.0

COPY app.py seed.py ./

# Drop privileges
USER appuser

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=3s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/health').status==200 else 1)"

# JWT_SECRET must be supplied at runtime (docker run -e JWT_SECRET=...).
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "app:app"]
