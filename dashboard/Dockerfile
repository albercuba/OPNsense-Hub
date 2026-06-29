FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends wireguard-tools iproute2 iptables nftables procps ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app/dashboard
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY migrations ./migrations
COPY alembic.ini ./alembic.ini
EXPOSE 8083
EXPOSE 51820/udp
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8083"]
