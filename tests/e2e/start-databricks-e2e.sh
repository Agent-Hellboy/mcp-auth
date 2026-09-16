#!/bin/sh
set -eu

openssl genrsa -out /var/lib/mcp-resource-auth/private.pem 2048 2>/dev/null
printf '%s\n' compose-e2e-key > /var/lib/mcp-resource-auth/key_id
chmod 0600 /var/lib/mcp-resource-auth/private.pem /var/lib/mcp-resource-auth/key_id

uvicorn mcp_databricks.app:app --host 127.0.0.1 --port 6329 &
uvicorn_pid=$!
nginx -c /app/nginx-databricks.conf -g 'daemon off;' &
nginx_pid=$!

trap 'kill "$uvicorn_pid" "$nginx_pid" 2>/dev/null || true; wait "$uvicorn_pid" "$nginx_pid" 2>/dev/null || true' INT TERM EXIT
wait "$nginx_pid"
