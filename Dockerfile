FROM python:3.11-slim

LABEL org.opencontainers.image.title="Lazarus Attestation Enclave"
LABEL org.opencontainers.image.description="Lazarus Protocol Isolated Ed25519 Enclave & 2-of-3 FROST Threshold Signer"
LABEL org.opencontainers.image.source="https://github.com/LazarusProtocol/attestation"
LABEL org.opencontainers.image.licenses="Apache-2.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY common ./common
COPY attestation ./attestation

EXPOSE 8085

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import os, urllib.request; p = os.environ.get('LAZARUS_ENCLAVE_PORT', '8085'); urllib.request.urlopen(f'http://127.0.0.1:{p}/health', timeout=3)" || exit 1

CMD ["python", "-m", "attestation.server"]

