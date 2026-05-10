#!/bin/bash
# Restore Kibana dashboards from export
set -e
set -a && source .env && set +a

KIBANA_URL=${KIBANA_URL:-http://localhost:5601}
EXPORT_FILE="kibana/dashboards/export.ndjson"

if [ ! -f "$EXPORT_FILE" ]; then
  echo "Export file not found: $EXPORT_FILE"
  exit 1
fi

echo "Importing Kibana dashboards from $EXPORT_FILE..."

curl -X POST "$KIBANA_URL/api/saved_objects/_import?overwrite=true" \
  -H "kbn-xsrf: true" \
  -u "$ELASTIC_USER:$ELASTIC_PASSWORD" \
  --form file=@"$EXPORT_FILE"

echo ""
echo "Import complete! Open Kibana and check your dashboards."
