#!/bin/sh
set -eu

# The private_key_jwt key pair is provisioned out of band by the
# resource-keygen service and mounted read-only, so its public half can be
# registered with mcp-auth (MCP_AUTH_RESOURCE_CLIENTS_FILE) before this
# resource server ever authenticates with it.
test -s /var/lib/mcp-resource-auth/private.pem
test -s /var/lib/mcp-resource-auth/key_id

uvicorn mcp_databricks.app:app --host 127.0.0.1 --port 6329 &
uvicorn_pid=$!
nginx -c /app/nginx-databricks.conf -g 'daemon off;' &
nginx_pid=$!

trap 'kill "$uvicorn_pid" "$nginx_pid" 2>/dev/null || true; wait "$uvicorn_pid" "$nginx_pid" 2>/dev/null || true' INT TERM EXIT
wait "$nginx_pid"
