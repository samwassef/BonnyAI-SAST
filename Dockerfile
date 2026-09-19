FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HF_HUB_DISABLE_TELEMETRY=1
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --uid 10001 --no-create-home app
COPY app ./app
COPY run_server.py ./
USER 10001:10001
EXPOSE 8000
CMD ["python", "run_server.py"]
