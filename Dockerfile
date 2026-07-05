# Nexus Controller — minimal, unprivileged container image.
# The controller never needs root or external binaries (cert generation uses the
# cryptography lib, not openssl), so this stays a tiny slim-python image.
FROM python:3.12-slim

# Dependencies first for layer caching.
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && rm /tmp/requirements.txt

# App.
WORKDIR /app
COPY app.py monitoring.py history.py ./
COPY adapters/ ./adapters/
COPY collectors/ ./collectors/
COPY templates/ ./templates/
COPY static/ ./static/

# Non-root runtime user; state lives in the mounted /data volume.
RUN useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin nexus \
    && mkdir -p /data && chown nexus:nexus /data
ENV CONTROLLER_DATA_DIR=/data \
    CONTROLLER_PORT=9443 \
    CONTROLLER_TLS=1
VOLUME ["/data"]
EXPOSE 9443
USER nexus

# Healthy = the SPA root answers (public, returns 200 regardless of auth/TLS).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import os,ssl,urllib.request; \
s='https' if os.environ.get('CONTROLLER_TLS','1')=='1' else 'http'; \
p=os.environ.get('CONTROLLER_PORT','9443'); \
urllib.request.urlopen(s+'://127.0.0.1:'+p+'/', context=ssl._create_unverified_context(), timeout=4)" || exit 1

CMD ["python", "app.py"]
