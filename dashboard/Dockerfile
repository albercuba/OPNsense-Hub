FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends wireguard-tools iproute2 iptables nftables procps ca-certificates && rm -rf /var/lib/apt/lists/*
RUN groupadd --system --gid 10001 opnsensehub && useradd --system --uid 10001 --gid opnsensehub --home-dir /app --shell /usr/sbin/nologin opnsensehub
WORKDIR /app/dashboard
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY migrations ./migrations
COPY alembic.ini ./alembic.ini
RUN mkdir -p /var/lib/opnsense-hub/branding && chown -R opnsensehub:opnsensehub /app /var/lib/opnsense-hub
USER 10001:10001
EXPOSE 8083
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8083"]
