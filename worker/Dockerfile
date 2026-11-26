FROM python:3.13-alpine
WORKDIR /w
RUN pip install --no-cache-dir psycopg2-binary
COPY worker.py .
RUN adduser -D -u 10001 appuser
USER appuser
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD pgrep -f worker.py > /dev/null || exit 1
CMD ["python", "worker.py"]
