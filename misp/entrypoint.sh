#!/usr/bin/env bash
set -euo pipefail

printenv | grep -E '^(ELASTIC_|MISP_|LOG_LEVEL|REFRESH_|PUSHER_)' \
    | sed 's/^/export /' \
    >> /etc/environment

cron
sleep 30

PUSHER_PAUSE_SECONDS="${PUSHER_PAUSE_SECONDS:-60}"

while true; do
    echo "[entrypoint] $(date -u +%Y-%m-%dT%H:%M:%SZ) — starting pusher run"
    python /app/misp_pusher.py 2>&1 | tee -a /var/log/misp_pusher.log
    echo "[entrypoint] $(date -u +%Y-%m-%dT%H:%M:%SZ) — pusher run finished, sleeping ${PUSHER_PAUSE_SECONDS}s"
    sleep "${PUSHER_PAUSE_SECONDS}"
done
