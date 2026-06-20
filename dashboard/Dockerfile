FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends wireguard-tools iproute2 ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app/dashboard
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY migrations ./migrations
EXPOSE 8082
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8082"]
