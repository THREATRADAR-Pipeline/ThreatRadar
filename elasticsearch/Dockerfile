FROM python:3.11-slim

WORKDIR /app

COPY elasticsearch/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY elasticsearch/ .

ENTRYPOINT ["bash", "/app/entrypoint.sh"]