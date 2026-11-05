#!/usr/bin/env bash
set -euo pipefail
image=${1:?image reference required}
container=$(docker run -d -e INKSON_STATION_URL=https://station.example "$image")
trap 'docker rm -f "$container" >/dev/null' EXIT
for attempt in $(seq 1 30); do
  if docker exec "$container" wget -qO /tmp/index.html http://127.0.0.1/; then
    break
  fi
  sleep 1
done
docker exec "$container" nginx -t
docker exec "$container" grep -F '<title>Inkson</title>' /tmp/index.html
docker exec "$container" grep -F 'name="inkson-station-url" content="https://station.example"' /tmp/index.html
docker exec "$container" wget -qO /tmp/route.html http://127.0.0.1/login
docker exec "$container" cmp /tmp/index.html /tmp/route.html
docker exec "$container" wget -qO /dev/null http://127.0.0.1/bootstrap.js
docker exec "$container" wget -qO /dev/null http://127.0.0.1/assets/pkg/inkson_bg.wasm
