#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
PORT="${PORT:-8888}"
docker build -t ctf-mojo-public .
docker rm -f ctf-public >/dev/null 2>&1 || true
docker run -d --name ctf-public -p "$PORT:8888" ctf-mojo-public >/dev/null
echo "[+] listening on $PORT  --  nc 127.0.0.1 $PORT"
echo "[+] stop with: docker rm -f ctf-public"
