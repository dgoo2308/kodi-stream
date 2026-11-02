#!/bin/bash
# Deploy the stream.nellika.io vhost to nell_remote. Sign-in comes from nellika-auth (auth.nellika.io,
# repo ~/git/nellika-auth), which must be deployed first: this vhost includes its nginx snippets.
# backup -> install -> nginx -t (restore on failure) -> reload -> checks.
# Usage: vps/deploy.sh            (from the repo root)
set -euo pipefail
cd "$(dirname "$0")/.."
SSH=(ssh nell_remote_root)

check() {
  curl -s -o /dev/null -w "stream.nellika.io/  =%{http_code} -> %{redirect_url} (expect 302 to auth.nellika.io)\n" https://stream.nellika.io/
}

echo "== before"; check
scp -q vps/stream.nellika.io.conf nell_remote_root:/root/
"${SSH[@]}" 'set -e
if [ ! -f /etc/nginx/snippets/nellika-auth-server.conf ] || ! systemctl is-active -q nellika-auth; then
  echo "nellika-auth is not installed: deploy ~/git/nellika-auth first"; exit 1
fi
B=/root/stream-vhost-backup-$(date +%Y%m%d-%H%M%S); mkdir -p $B
cp /etc/nginx/conf.d/stream.nellika.io.conf $B/
echo "backup: $B"
install -m 644 /root/stream.nellika.io.conf /etc/nginx/conf.d/stream.nellika.io.conf
if ! nginx -t; then
  echo "nginx -t FAILED: restoring the vhost"; cp $B/stream.nellika.io.conf /etc/nginx/conf.d/; exit 1
fi
systemctl reload nginx'

sleep 2
echo "== after"; check
