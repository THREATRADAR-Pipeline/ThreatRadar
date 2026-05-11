FROM python:3.11-slim

WORKDIR /app

COPY poisoning_detection/requirements.txt /app/requirements.txt

RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir \
    --timeout 120 \
    --retries 5 \
    -r /app/requirements.txt

COPY . /app

RUN mkdir -p /app/poisoning_detection/output /app/poisoning_detection/models

ENTRYPOINT ["python", "-u", "/app/poisoning_detection/pipeline/run_pipeline_production.py"]