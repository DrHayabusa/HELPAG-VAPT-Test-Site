FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --system lab && useradd --system --gid lab --create-home lab
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py ./app.py
COPY templates ./templates
COPY static ./static

RUN mkdir -p /app/logs && chown -R lab:lab /app
USER lab

EXPOSE 5005
HEALTHCHECK --interval=10s --timeout=3s --retries=5 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5005/health', timeout=2)"
CMD ["python", "app.py"]

