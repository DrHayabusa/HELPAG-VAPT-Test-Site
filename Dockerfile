FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# iputils-ping backs the command-injection challenge; without it the injected
# command still runs but the legitimate path produces no output.
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system lab && useradd --system --gid lab --create-home lab
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py ./app.py
COPY labsite ./labsite
COPY templates ./templates
COPY static ./static
COPY public_docs ./public_docs
COPY backups ./backups
COPY flagstore ./flagstore
COPY tools ./tools

RUN mkdir -p /app/logs /app/uploads && chown -R lab:lab /app
USER lab

EXPOSE 5005
HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5005/health', timeout=2)"
CMD ["python", "app.py"]
