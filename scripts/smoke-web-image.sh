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
headers=$(docker exec "$container" wget -S --header='Accept-Encoding: gzip' -O /tmp/inkson.wasm.gz http://127.0.0.1/assets/pkg/inkson_bg.wasm 2>&1)
printf '%s\n' "$headers" | grep -i 'Content-Encoding: gzip'
printf '%s\n' "$headers" | grep -i 'Vary: Accept-Encoding'
docker exec "$container" sh -ec 'gzip -dc /tmp/inkson.wasm.gz > /tmp/inkson.wasm; cmp /tmp/inkson.wasm /usr/share/nginx/html/assets/pkg/inkson_bg.wasm'
docker exec "$container" sh -ec 'test "$(wc -c < /tmp/inkson.wasm.gz)" -lt "$(wc -c < /tmp/inkson.wasm)"'
headers=$(docker exec "$container" wget -S --header='Accept-Encoding: gzip' -O /tmp/index.html.gz http://127.0.0.1/ 2>&1)
if printf '%s\n' "$headers" | grep -qi 'Content-Encoding: gzip'; then
  docker exec "$container" sh -ec 'gzip -dc /tmp/index.html.gz > /tmp/index-decoded.html'
else
  docker exec "$container" cp /tmp/index.html.gz /tmp/index-decoded.html
fi
docker exec "$container" grep -F 'name="inkson-station-url" content="https://station.example"' /tmp/index-decoded.html
