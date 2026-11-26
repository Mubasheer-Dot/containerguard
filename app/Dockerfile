FROM python:3.13-alpine
WORKDIR /app
RUN pip install --no-cache-dir flask psycopg2-binary
COPY app.py .
RUN adduser -D -u 10001 appuser
USER appuser
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD wget -qO- http://127.0.0.1:5000/health || exit 1
CMD ["python", "app.py"]
