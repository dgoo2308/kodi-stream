#!/bin/bash
# Deploy this checkout to the Kodi box: backup -> install -> nginx -t -> reload -> restart -> health.
# Remote access (frp -> 127.0.0.1:8088 -> stream.nellika.io) must stay up: checked before and after.
# Usage: scripts/deploy.sh            (from the repo root)
set -euo pipefail
cd "$(dirname "$0")/.."
SSH=(ssh -J nell_remote_root -p 6043 root@127.0.0.1)
SCP=(scp -q -o ProxyJump=nell_remote_root -P 6043)

check() {
  "${SSH[@]}" 'curl -s -o /dev/null -w "box 8088 health=%{http_code}\n" http://127.0.0.1:8088/api/health;
               curl -s -o /dev/null -w "box LAN  health=%{http_code}\n" http://127.0.0.1/api/health'
  curl -s -o /dev/null -w "VPS stream.nellika.io=%{http_code} (expect 302)\n" https://stream.nellika.io/
}

echo "== before"; check
echo "== active session (a restart ends it):"; "${SSH[@]}" 'curl -s http://127.0.0.1:8090/api/session; echo'

"${SCP[@]}" stream-api.py static/index.html nginx-kodi-stream.conf nginx-kodi-stream-lan.conf root@127.0.0.1:/root/
"${SSH[@]}" 'set -e
B=/root/kodi-stream-backup-$(date +%Y%m%d-%H%M%S); mkdir -p $B
cp /opt/kodi-stream/stream-api.py /opt/kodi-stream/config.json /opt/kodi-stream/static/index.html \
   /etc/nginx/sites-available/kodi-stream /etc/nginx/sites-available/kodi-stream-lan $B/
echo "backup: $B"
install -m 644 /root/stream-api.py /opt/kodi-stream/stream-api.py
install -m 644 /root/index.html /opt/kodi-stream/static/index.html
install -m 644 /root/nginx-kodi-stream.conf /etc/nginx/sites-available/kodi-stream
install -m 644 /root/nginx-kodi-stream-lan.conf /etc/nginx/sites-available/kodi-stream-lan
install -d -o pi -g pi -m 755 /home/pi/kodi-stream-dl
# old box config pinned real-time pacing (pace_realtime: true); sessions are now encoded ahead
grep -q pace_readrate /opt/kodi-stream/config.json || echo "{\"pace_readrate\": 0}" > /opt/kodi-stream/config.json
if ! nginx -t; then
  echo "nginx -t FAILED: restoring nginx sites from $B"
  cp $B/kodi-stream $B/kodi-stream-lan /etc/nginx/sites-available/; exit 1
fi
systemctl reload nginx
systemctl restart kodi-stream; sleep 3; systemctl is-active kodi-stream
journalctl -u kodi-stream -n 3 --no-pager'

echo "== after"; check
echo "Rollback if needed: copy the backup dir above back into /opt/kodi-stream + /etc/nginx/sites-available, reload nginx, restart kodi-stream"
