#!/bin/bash
# Deploy nellika-auth (auth.nellika.io) to nell_remote, replacing stream-auth on 127.0.0.1:8091.
# backup -> venv -> DB copy (first time) -> swap services (old one back on failure) -> nginx (restore on
# nginx -t failure) -> checks. Re-runnable: later runs just update the code and configs.
# Usage: vps/deploy-nellika-auth.sh            (from the repo root)
set -euo pipefail
cd "$(dirname "$0")/.."
SSH=(ssh nell_remote_root)

check() {
  curl -s -o /dev/null -w "stream.nellika.io/            =%{http_code} -> %{redirect_url}\n" https://stream.nellika.io/
  curl -s -o /dev/null -w "auth.nellika.io/login         =%{http_code}\n" https://auth.nellika.io/login
}

echo "== before"; check || true
scp -q vps/nellika-auth.py vps/nellika-auth.service vps/auth.nellika.io.conf vps/stream.nellika.io.conf \
    vps/snippets/nellika-auth-server.conf vps/snippets/nellika-auth-location.conf nell_remote_root:/root/
"${SSH[@]}" 'set -e
B=/root/nellika-auth-backup-$(date +%Y%m%d-%H%M%S); mkdir -p $B
cp -a /etc/nginx/conf.d/stream.nellika.io.conf $B/
[ -f /etc/nginx/conf.d/auth.nellika.io.conf ] && cp -a /etc/nginx/conf.d/auth.nellika.io.conf $B/ || true
[ -d /etc/nginx/snippets ] && cp -a /etc/nginx/snippets $B/snippets || true
[ -f /var/lib/stream-auth/auth.db ] && /usr/bin/python3.11 -c "import sqlite3,sys; s=sqlite3.connect(sys.argv[1]); d=sqlite3.connect(sys.argv[2]); s.backup(d)" /var/lib/stream-auth/auth.db $B/stream-auth.db
[ -f /var/lib/nellika-auth/auth.db ] && /usr/bin/python3.11 -c "import sqlite3,sys; s=sqlite3.connect(sys.argv[1]); d=sqlite3.connect(sys.argv[2]); s.backup(d)" /var/lib/nellika-auth/auth.db $B/nellika-auth.db
echo "backup: $B"

install -d -m 755 /opt/nellika-auth
[ -x /opt/nellika-auth/venv/bin/python ] || python3.11 -m venv /opt/nellika-auth/venv
/opt/nellika-auth/venv/bin/pip install -q "webauthn>=2.2,<3" "segno>=1.6,<2"
/opt/nellika-auth/venv/bin/python -c "import ast; ast.parse(open(\"/root/nellika-auth.py\").read())"
install -m 644 /root/nellika-auth.py /opt/nellika-auth/nellika-auth.py
install -m 644 /root/nellika-auth.service /etc/systemd/system/nellika-auth.service

# first run: take over the stream-auth database (users, passkeys, devices) with a consistent copy
install -d -m 700 /var/lib/nellika-auth
if [ ! -f /var/lib/nellika-auth/auth.db ] && [ -f /var/lib/stream-auth/auth.db ]; then
  /usr/bin/python3.11 -c "import sqlite3,sys; s=sqlite3.connect(sys.argv[1]); d=sqlite3.connect(sys.argv[2]); s.backup(d)" /var/lib/stream-auth/auth.db /var/lib/nellika-auth/auth.db
  chmod 600 /var/lib/nellika-auth/auth.db
  echo "database copied from stream-auth"
fi

systemctl daemon-reload
if systemctl is-active -q stream-auth; then systemctl stop stream-auth; fi
systemctl enable -q nellika-auth
systemctl restart nellika-auth; sleep 2
if ! systemctl is-active -q nellika-auth || ! curl -s -o /dev/null -H "Host: auth.nellika.io" http://127.0.0.1:8091/login; then
  echo "nellika-auth FAILED: back to stream-auth"; journalctl -u nellika-auth -n 30 --no-pager
  systemctl stop nellika-auth || true; systemctl start stream-auth; exit 1
fi
systemctl disable -q stream-auth 2>/dev/null || true

install -d -m 755 /etc/nginx/snippets
install -m 644 /root/nellika-auth-server.conf /root/nellika-auth-location.conf /etc/nginx/snippets/
install -m 644 /root/auth.nellika.io.conf /etc/nginx/conf.d/auth.nellika.io.conf
install -m 644 /root/stream.nellika.io.conf /etc/nginx/conf.d/stream.nellika.io.conf
if ! nginx -t; then
  echo "nginx -t FAILED: restoring the previous configs"
  cp -a $B/stream.nellika.io.conf /etc/nginx/conf.d/
  if [ -f $B/auth.nellika.io.conf ]; then cp -a $B/auth.nellika.io.conf /etc/nginx/conf.d/; else rm -f /etc/nginx/conf.d/auth.nellika.io.conf; fi
  if [ ! -f $B/auth.nellika.io.conf ]; then   # first rollout: the old stream vhost needs the old service
    echo "first rollout: back to stream-auth"; systemctl stop nellika-auth; systemctl disable -q nellika-auth
    systemctl enable -q stream-auth; systemctl start stream-auth
  fi
  nginx -t && systemctl reload nginx
  exit 1
fi
systemctl reload nginx
echo "nellika-auth: $(systemctl is-active nellika-auth), stream-auth: $(systemctl is-active stream-auth || true)"'

echo "== after"; check
