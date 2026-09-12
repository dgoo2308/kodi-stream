#!/usr/bin/env python3
"""stream.nellika.io cookie login (VPS-side). Serves an HTML login form that iOS
Keychain can autofill/store, validates against the shared htpasswd, and sets a
signed cookie. nginx uses /_authcheck (auth_request) to allow cookie'd requests,
with Basic auth kept as a fallback (satisfy any). Standard library only."""
import base64, hashlib, hmac, os, subprocess, time, urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

HTPASSWD = "/etc/nginx/torrent-add.htpasswd"
KEYFILE  = "/etc/stream-auth.key"
COOKIE   = "stream_auth"
MAXAGE   = 90 * 24 * 3600
PORT     = 8091

with open(KEYFILE, "rb") as f:
    SECRET = f.read().strip()


def _b64e(b): return base64.urlsafe_b64encode(b).decode().rstrip("=")
def _b64d(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def make_token(user):
    exp = int(time.time()) + MAXAGE
    msg = ("%s|%d" % (user, exp)).encode()
    mac = hmac.new(SECRET, msg, hashlib.sha256).digest()
    return _b64e(msg) + "." + _b64e(mac)


def check_token(tok):
    try:
        body, mac = tok.split(".", 1)
        msg = _b64d(body)
        if not hmac.compare_digest(_b64d(mac), hmac.new(SECRET, msg, hashlib.sha256).digest()):
            return None
        user, exp = msg.decode().split("|")
        return user if int(exp) > time.time() else None
    except Exception:
        return None


def valid_login(user, pw):
    if not user or "\n" in user or ":" in user or len(user) > 64:
        return False
    try:
        r = subprocess.run(["htpasswd", "-vi", HTPASSWD, user], input=pw,
                           universal_newlines=True, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=5)  # py3.6: text/capture_output unsupported
        return r.returncode == 0
    except Exception:
        return False


def safe_next(n):
    n = n or "/"
    return n if n.startswith("/") and not n.startswith("//") else "/"


FORM = """<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name=apple-mobile-web-app-capable content=yes>
<title>Nellika Stream</title>
<style>body{{font-family:-apple-system,system-ui,sans-serif;background:#111;color:#eee;display:flex;min-height:100vh;margin:0;align-items:center;justify-content:center}}
form{{background:#1b1b1b;padding:28px 24px;border-radius:16px;width:290px;max-width:86vw}}
h1{{font-size:19px;margin:0 0 4px}}p{{color:#999;font-size:13px;margin:0 0 14px}}
input{{width:100%;box-sizing:border-box;padding:12px;margin:6px 0;border-radius:10px;border:1px solid #444;background:#222;color:#eee;font-size:16px}}
button{{width:100%;padding:13px;margin-top:14px;border:0;border-radius:10px;background:#4da3ff;color:#000;font-weight:600;font-size:16px}}
.err{{color:#f66;font-size:13px;min-height:16px;margin-top:8px}}</style></head>
<body><form method=post action=/_login accept-charset=utf-8>
<h1>Nellika Stream</h1><p>Sign in to watch your library.</p>
<input type=hidden name=next value="{next}">
<input name=username autocomplete=username autocapitalize=none autocorrect=off spellcheck=false placeholder=Username required autofocus>
<input name=password type=password autocomplete=current-password placeholder=Password required>
<div class=err>{err}</div>
<button type=submit>Sign in</button>
</form></body></html>"""


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code, body=b"", ctype="text/html; charset=utf-8", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _cookie_user(self):
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                if k == COOKIE:
                    return check_token(v)
        return None

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/_authcheck":
            return self._send(200 if self._cookie_user() else 401, b"")
        if path == "/_logout":
            return self._send(302, b"", extra=[
                ("Set-Cookie", "%s=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax" % COOKIE),
                ("Location", "/_login")])
        if path == "/_login":
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            nxt = safe_next((q.get("next") or ["/"])[0])
            html = FORM.format(next=nxt.replace('"', "%22"), err="")
            return self._send(200, html.encode())
        return self._send(404, b"not found")

    def do_POST(self):
        if urllib.parse.urlparse(self.path).path != "/_login":
            return self._send(404, b"not found")
        n = int(self.headers.get("Content-Length") or 0)
        data = urllib.parse.parse_qs(self.rfile.read(n).decode("utf-8", "replace"))
        user = (data.get("username") or [""])[0].strip()
        pw = (data.get("password") or [""])[0]
        nxt = safe_next((data.get("next") or ["/"])[0])
        if valid_login(user, pw):
            cookie = "%s=%s; Path=/; Max-Age=%d; HttpOnly; Secure; SameSite=Lax" % (COOKIE, make_token(user), MAXAGE)
            return self._send(302, b"", extra=[("Set-Cookie", cookie), ("Location", nxt)])
        html = FORM.format(next=nxt.replace('"', "%22"), err="Wrong username or password.")
        return self._send(401, html.encode())

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
