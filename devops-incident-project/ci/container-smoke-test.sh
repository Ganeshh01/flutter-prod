#!/usr/bin/env bash
# Smoke tests for the built image. Local only: runs a throwaway container on a
# loopback port and removes it afterwards. Does not push or deploy anything.
#
# Usage: ci/container-smoke-test.sh [image] [host_port]
set -u
# Git Bash on Windows rewrites arguments like /tmp into C:/... paths; turn that off.
export MSYS_NO_PATHCONV=1

IMAGE="${1:-food-delivery-ui:local}"
PORT="${2:-18080}"
NAME="smoke-$$"
FAILS=0

pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; FAILS=$((FAILS + 1)); }
check() { if eval "$2"; then pass "$1"; else fail "$1"; fi; }

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1; }
trap cleanup EXIT

docker image inspect "$IMAGE" >/dev/null 2>&1 || { echo "image $IMAGE not found - build it first"; exit 2; }

# Bind to 127.0.0.1 only so the test container is not reachable from the network.
docker run -d --name "$NAME" -p "127.0.0.1:${PORT}:8080" --read-only \
  --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges "$IMAGE" >/dev/null \
  || { echo "container failed to start"; exit 2; }

# Wait up to 30s for the app to answer.
for _ in $(seq 1 30); do
  curl -fs -o /dev/null "http://127.0.0.1:${PORT}/healthz" && break
  sleep 1
done

BASE="http://127.0.0.1:${PORT}"

# 1. Runs as non-root
UID_IN_CONTAINER="$(docker exec "$NAME" id -u)"
check "process runs as non-root (uid=$UID_IN_CONTAINER)" '[ "$UID_IN_CONTAINER" != "0" ]'
check "image config sets a non-root USER" '[ -n "$(docker image inspect -f "{{.Config.User}}" "$IMAGE")" ] && [ "$(docker image inspect -f "{{.Config.User}}" "$IMAGE")" != "root" ] && [ "$(docker image inspect -f "{{.Config.User}}" "$IMAGE")" != "0" ]'

# 2. Health endpoint
check "/healthz returns 200" '[ "$(curl -s -o /dev/null -w "%{http_code}" "$BASE/healthz")" = "200" ]'
check "/healthz body is 'ok'" '[ "$(curl -s "$BASE/healthz")" = "ok" ]'

# 3. App is served
check "/ returns 200 with HTML" 'curl -s -i "$BASE/" | head -20 | grep -qi "content-type: text/html" && [ "$(curl -s -o /dev/null -w "%{http_code}" "$BASE/")" = "200" ]'
check "unknown route falls back to index.html (SPA)" '[ "$(curl -s -o /dev/null -w "%{http_code}" "$BASE/no/such/route")" = "200" ]'
check "main.dart.js is served" '[ "$(curl -s -o /dev/null -w "%{http_code}" "$BASE/main.dart.js")" = "200" ]'

# 4. Hardening
HEADERS="$(curl -s -i "$BASE/")"
check "X-Content-Type-Options header present" 'echo "$HEADERS" | grep -qi "^x-content-type-options: nosniff"'
check "X-Frame-Options header present" 'echo "$HEADERS" | grep -qi "^x-frame-options: DENY"'
check "nginx version not disclosed" '! echo "$HEADERS" | grep -qiE "^server: nginx/[0-9]"'
check "index.html is not cached" 'echo "$HEADERS" | grep -qi "^cache-control: no-cache"'

# 5. No secrets or sources in the image
check "no secret-like files in served content" '[ -z "$(docker exec "$NAME" find /usr/share/nginx/html /etc/nginx -type f \( -name ".env*" -o -name "*.pem" -o -name "*.key" -o -name "*.jks" -o -name "*.keystore" -o -name "key.properties" \) 2>/dev/null)" ]'
check "no dart sources in image (build stage not shipped)" '[ -z "$(docker exec "$NAME" find / -xdev -name "*.dart" -not -name "*.dart.js" -not -path "/proc/*" 2>/dev/null | head -1)" ]'
check "no Flutter SDK in image" '! docker exec "$NAME" sh -c "command -v flutter" >/dev/null 2>&1'

# 6. Container healthcheck goes healthy (start-period 5s, interval 30s -> allow time)
for _ in $(seq 1 45); do
  STATE="$(docker inspect -f '{{.State.Health.Status}}' "$NAME" 2>/dev/null)"
  [ "$STATE" = "healthy" ] && break
  sleep 2
done
check "docker HEALTHCHECK reports healthy (got: ${STATE:-none})" '[ "$STATE" = "healthy" ]'

echo
if [ "$FAILS" -eq 0 ]; then echo "All checks passed."; else echo "$FAILS check(s) failed."; fi
exit "$FAILS"
