set -uo pipefail


ES_URL="${ELASTIC_HOST:-http://elasticsearch:9200}"
ES_USER="${ELASTIC_USER:-elastic}"
ES_PASS="${ELASTIC_PASSWORD:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${SCRIPT_DIR}/pipeline_$(date +%Y%m%d_%H%M%S).log"
PIPELINE_FAILED=0

if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; RESET=''
fi

log()  { echo -e "$(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOG_FILE"; }
info() { log "${CYAN}[INFO]${RESET}  $*"; }
ok()   { log "${GREEN}[OK]${RESET}    $*"; }
warn() { log "${YELLOW}[WARN]${RESET}  $*"; }
fail() { log "${RED}[FAIL]${RESET}  $*"; }
sep()  { log "${BOLD}=======================================================${RESET}"; }

check_credentials() {
    if [ -z "${ES_PASS}" ]; then
        fail "ELASTIC_PASSWORD is not set — cannot authenticate."
        fail "Set ELASTIC_PASSWORD in your .env file and restart."
        exit 1
    fi
}


pause_scorer() {
    info "Pausing scorer container to free resources ..."
    local result
    result=$(python3 -c "
import urllib.request, socket, json

class UnixSocketHTTPConnection:
    def __init__(self): pass

import http.client

class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self):
        super().__init__('localhost')
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect('/var/run/docker.sock')

conn = UnixHTTPConnection()
conn.request('POST', '/containers/scorer/stop')
r = conn.getresponse()
print(r.status)
" 2>&1)
    if echo "$result" | grep -qE "^(204|304)"; then
        ok "Scorer paused"
    else
        warn "Scorer not running or could not be stopped (non-fatal)"
    fi
}

resume_scorer() {
    info "Resuming scorer ..."
    local result
    result=$(python3 -c "
import socket, http.client

class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self):
        super().__init__('localhost')
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect('/var/run/docker.sock')

conn = UnixHTTPConnection()
conn.request('POST', '/containers/scorer/start')
r = conn.getresponse()
print(r.status)
" 2>&1)
    if echo "$result" | grep -qE "^(204|304)"; then
        ok "Scorer resumed "
    else
        warn "Could not resume scorer (non-fatal — start it manually)"
    fi
}


wait_for_es() {
    local max_attempts=30
    local attempt=0

    info "Waiting for Elasticsearch at ${ES_URL} ..."

    until ELASTIC_HOST="${ES_URL}" \
          ELASTIC_USER="${ES_USER}" \
          ELASTIC_PASSWORD="${ES_PASS}" \
          python3 - << 'PYEOF'
import os, sys, urllib.request, urllib.error, json, base64

host  = os.environ["ELASTIC_HOST"]
user  = os.environ["ELASTIC_USER"]
pwd   = os.environ["ELASTIC_PASSWORD"]
creds = base64.b64encode(f"{user}:{pwd}".encode()).decode()
url   = f"{host}/_cluster/health?wait_for_status=yellow&timeout=5s"
req   = urllib.request.Request(url, headers={"Authorization": f"Basic {creds}"})
try:
    with urllib.request.urlopen(req, timeout=10) as r:
        h = json.loads(r.read())
    sys.exit(0 if h.get("status") in ("yellow", "green") else 1)
except Exception:
    sys.exit(1)
PYEOF
    do
        attempt=$(( attempt + 1 ))
        if [ "$attempt" -ge "$max_attempts" ]; then
            fail "Elasticsearch not ready after $(( max_attempts * 10 ))s — aborting."
            exit 2
        fi
        warn "  ES not ready (attempt ${attempt}/${max_attempts}) — retrying in 10s ..."
        sleep 10
    done

    ok "Elasticsearch is up and healthy"
}


register_painless_script() {
    info "Registering Painless upsert script ..."

    ELASTIC_HOST="${ES_URL}" \
    ELASTIC_USER="${ES_USER}" \
    ELASTIC_PASSWORD="${ES_PASS}" \
    python3 /dev/stdin << 'PYEOF'
import os, sys, json, base64, urllib.request, urllib.error

host  = os.environ["ELASTIC_HOST"]
user  = os.environ["ELASTIC_USER"]
pwd   = os.environ["ELASTIC_PASSWORD"]
creds = base64.b64encode(f"{user}:{pwd}".encode()).decode()

script_source = (
    "if (ctx._source.sources == null) { ctx._source.sources = []; } "
    "boolean found = false; "
    "for (s in ctx._source.sources) { if (s.feed_name == params.source.feed_name) { found = true; break; } } "
    "if (!found) { "
    "ctx._source.sources.add(params.source); "
    "ctx._source.source_count = ctx._source.sources.length; "
    "if (ctx._source.source_names == null) { ctx._source.source_names = []; } "
    "if (!ctx._source.source_names.contains(params.source.feed_name)) { ctx._source.source_names.add(params.source.feed_name); } "
    "if (params.source.feed_reputation != null) { "
    "if (ctx._source.source_confidence == null || params.source.feed_reputation > ctx._source.source_confidence) { "
    "ctx._source.source_confidence = params.source.feed_reputation; } } }"
)

body = json.dumps({"script": {"lang": "painless", "source": script_source}}).encode()
req  = urllib.request.Request(
    f"{host}/_scripts/ti_upsert_source",
    data    = body,
    method  = "PUT",
    headers = {"Authorization": f"Basic {creds}", "Content-Type": "application/json"},
)
try:
    urllib.request.urlopen(req, timeout=10)
    sys.exit(0)
except urllib.error.HTTPError as e:
    print(f"HTTP {e.code}: {e.read().decode()}", file=sys.stderr)
    sys.exit(1)
except Exception as e:
    print(str(e), file=sys.stderr)
    sys.exit(1)
PYEOF

    local rc=$?
    if [ $rc -eq 0 ]; then
        ok "Painless script registered "
    else
        warn "Painless script registration failed (non-fatal — processor has inline fallback)"
    fi
}


wait_for_filebeat() {
    local max_attempts=18
    local attempt=0

    info "Waiting for Filebeat to populate raw indices (max 3 min) ..."

    until ELASTIC_HOST="${ES_URL}" \
          ELASTIC_USER="${ES_USER}" \
          ELASTIC_PASSWORD="${ES_PASS}" \
          python3 - << 'PYEOF'
import os, sys, urllib.request, json, base64

host  = os.environ["ELASTIC_HOST"]
user  = os.environ["ELASTIC_USER"]
pwd   = os.environ["ELASTIC_PASSWORD"]
creds = base64.b64encode(f"{user}:{pwd}".encode()).decode()

for pattern in ("ti_feodo-*", "ti_otx-*", "ti_abuseurl-*", "ti_cisa-*"):
    url = f"{host}/{pattern}/_count"
    req = urllib.request.Request(url, headers={"Authorization": f"Basic {creds}"})
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            if json.loads(r.read()).get("count", 0) > 0:
                sys.exit(0)
    except Exception:
        pass
sys.exit(1)
PYEOF
    do
        attempt=$(( attempt + 1 ))
        if [ "$attempt" -ge "$max_attempts" ]; then
            warn "Filebeat raw indices still empty after 3 min — proceeding."
            warn "Pipeline may have partial data if Filebeat is still starting."
            return
        fi
        info "  Filebeat not ready yet (attempt ${attempt}/${max_attempts}) — waiting 10s ..."
        sleep 10
    done

    ok "Filebeat raw indices populated "
}


run_step() {
    local step_num="$1"
    local label="$2"
    local script="$3"
    local exit_code elapsed start

    sep
    info "Step ${step_num}: ${label}"
    sep

    start=$(date +%s)
    python3 "${SCRIPT_DIR}/${script}" 2>&1 | tee -a "$LOG_FILE"
    exit_code="${PIPESTATUS[0]}"
    elapsed=$(( $(date +%s) - start ))

    if [ "$exit_code" -eq 0 ]; then
        ok "${label} completed in ${elapsed}s"
    else
        fail "${label} FAILED (exit ${exit_code}) after ${elapsed}s"
        PIPELINE_FAILED=1
    fi
}



PIPELINE_START=$(date +%s)

sep
info "THREATRADAR Pipeline starting — log: $(basename ${LOG_FILE})"
sep

check_credentials
wait_for_es
pause_scorer
register_painless_script

sep
info "Step 0: retention.py       (180-day stale data cleanup)"
sep
RETENTION_START=$(date +%s)
ELASTIC_HOST="${ES_URL}" \
ELASTIC_USER="${ES_USER}" \
ELASTIC_PASSWORD="${ES_PASS}" \
python3 "${SCRIPT_DIR}/data_retention/retention.py" 2>&1 | tee -a "$LOG_FILE"
RETENTION_RC="${PIPESTATUS[0]}"
RETENTION_ELAPSED=$(( $(date +%s) - RETENTION_START ))

if [ "$RETENTION_RC" -eq 0 ]; then
    ok "retention.py completed in ${RETENTION_ELAPSED}s"
elif [ "$RETENTION_RC" -eq 1 ]; then
    warn "retention.py finished with minor errors in ${RETENTION_ELAPSED}s (non-fatal — pipeline continues)"
    warn "Check ${LOG_FILE} or ti_retention_log index for details."
else
    warn "retention.py reported MAJOR errors (exit ${RETENTION_RC}) in ${RETENTION_ELAPSED}s"
    warn "More than 50% of indices were affected — check ti_retention_log immediately."
    warn "Pipeline will continue but stale data may not have been fully purged."
fi

wait_for_filebeat

run_step 1 "new_feeds.py       (external feeds → raw indices)" "data_ingestion/new_feeds.py"
if [ "$PIPELINE_FAILED" -eq 1 ]; then
    fail "Step 1 failed — aborting. Check network connectivity to feed endpoints."
    resume_scorer
    exit 1
fi


run_step 2 "news_ioc_feeder.py (News & Blog IOCs → staging index)"     "data_ingestion/news_ioc_feeder.py"
run_step 3 "ti_processor.py    (normalize + deduplicate)"       "data_normalization/ti_processor.py"
run_step 4 "enricher.py        (MITRE + OWASP + NVD + Threat Actor Activity Insights)"          "data_enrichment/enricher.py"

PIPELINE_ELAPSED=$(( $(date +%s) - PIPELINE_START ))

resume_scorer

sep
if [ "$PIPELINE_FAILED" -eq 0 ]; then
    ok "Pipeline complete in ${PIPELINE_ELAPSED}s "
else
    warn "Pipeline finished with errors in ${PIPELINE_ELAPSED}s — see ${LOG_FILE}"
fi
sep


SLEEP_SECONDS=$(( 7 * 24 * 60 * 60 ))
info "Next run in 7 days. Sleeping ${SLEEP_SECONDS}s ..."
sleep ${SLEEP_SECONDS}
