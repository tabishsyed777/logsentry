FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY logsentry.py /app/logsentry.py
RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /reports \
    && chown appuser:appuser /reports

USER appuser
ENTRYPOINT ["python", "/app/logsentry.py"]
