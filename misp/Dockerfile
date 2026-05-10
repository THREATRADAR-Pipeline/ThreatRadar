FROM python:3.11-slim
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends cron curl \
    && rm -rf /var/lib/apt/lists/*

COPY misp/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY misp/misp_helpers.py .
COPY misp/misp_pusher.py .
COPY misp/misp_daily_refresh.py .
COPY common.py .
COPY misp/entrypoint.sh .
RUN chmod +x entrypoint.sh

RUN printf '%s\n' \
    '0 2 * * * root . /etc/environment; cd /app && python misp_daily_refresh.py >> /var/log/misp_daily_refresh.log 2>&1' \
    '' \
    > /etc/cron.d/misp-jobs \
    && chmod 0644 /etc/cron.d/misp-jobs

RUN printf '%s\n' \
    '/var/log/misp_pusher.log /var/log/misp_daily_refresh.log {' \
    '    daily' \
    '    rotate 7' \
    '    compress' \
    '    missingok' \
    '    notifempty' \
    '    copytruncate' \
    '}' \
    > /etc/logrotate.d/misp-jobs

CMD ["./entrypoint.sh"]
