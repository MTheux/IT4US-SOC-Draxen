FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 EASM_HOST=0.0.0.0 EASM_PORT=8765 EASM_DB_PATH=/data/easm.sqlite
WORKDIR /app
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt && useradd --system --uid 10001 --home-dir /nonexistent easm && mkdir /data && chown 10001:10001 /data
COPY --chown=10001:10001 app ./app
COPY --chown=10001:10001 web ./web
COPY --chown=10001:10001 soc_easm.py ./soc_easm.py
USER 10001:10001
EXPOSE 8765
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8765", "--workers", "1", "--proxy-headers", "--forwarded-allow-ips", "*"]
