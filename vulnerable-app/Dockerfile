# A05: Insecure container build — Trivy config scan will flag these.
#  - Full "latest" base image (large attack surface, unpinned)
#  - Runs as root (no USER)
#  - Secrets baked via ENV
#  - No healthcheck, pip as root
FROM python:latest

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# A05: secret baked into the image layers
ENV JWT_SECRET="sup3r-s3cr3t-jwt-signing-key-do-not-share"

EXPOSE 5000
# Runs as root, debug server
CMD ["python", "app.py"]
