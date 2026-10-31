#!/bin/bash
# Deploy the VPS side (stream-auth + the stream.nellika.io vhost) to nell_remote_root.
# backup -> venv -> install -> service restart -> nginx -t (restore on failure) -> reload -> checks.
# Usage: vps/deploy.sh            (from the repo root)
set -euo pipefail
cd "$(dirname "$0")/.."
SSH=(ssh nell_remote_root)

check() {
  curl -s -o /dev/null -w "stream.nellika.io/        =%{http_code} (expect 302)\n" https://stream.nellika.io/
  curl -s -o /dev/null -w "stream.nellika.io/_login  =%{http_code} (expect 200)\n" https://stream.nellika.io/_login
}

echo "== before"; check
scp -q vps/stream-auth.py vps/stream-auth.service vps/stream.nellika.io.conf nell_remote_root:/root/
"${SSH[@]}" 'set -e
B=/root/stream-auth-backup-$(date +%Y%m%d-%H%M%S); mkdir -p $B
cp /opt/stream-auth/stream-auth.py /etc/systemd/system/stream-auth.service /etc/nginx/conf.d/stream.nellika.io.conf $B/
echo "backup: $B"
if [ ! -x /opt/stream-auth/venv/bin/python ]; then python3.11 -m venv /opt/stream-auth/venv; fi
/opt/stream-auth/venv/bin/pip install -q "webauthn>=2.2,<3" "segno>=1.6,<2"
/opt/stream-auth/venv/bin/python -c "import ast,sys; ast.parse(open(\"/root/stream-auth.py\").read())"
install -d -m 700 /var/lib/stream-auth
install -m 644 /root/stream-auth.py /opt/stream-auth/stream-auth.py
install -m 644 /root/stream-auth.service /etc/systemd/system/stream-auth.service
systemctl daemon-reload
systemctl restart stream-auth; sleep 2
if ! systemctl is-active -q stream-auth; then
  echo "stream-auth FAILED to start: restoring"; journalctl -u stream-auth -n 20 --no-pager
  cp $B/stream-auth.py /opt/stream-auth/; cp $B/stream-auth.service /etc/systemd/system/
  systemctl daemon-reload; systemctl restart stream-auth; exit 1
fi
install -m 644 /root/stream.nellika.io.conf /etc/nginx/conf.d/stream.nellika.io.conf
if ! nginx -t; then
  echo "nginx -t FAILED: restoring the vhost"; cp $B/stream.nellika.io.conf /etc/nginx/conf.d/; exit 1
fi
systemctl reload nginx
echo "stream-auth: $(systemctl is-active stream-auth)"'

echo "== after"; check
