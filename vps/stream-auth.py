#!/usr/bin/env python3
"""stream.nellika.io sign-in (VPS-side), behind nginx auth_request.

Ways in:
- passkey (WebAuthn, Face ID / fingerprint; rp id nellika.io so other *.nellika.io apps can share it)
- password: a stream-only htpasswd (NOT the transmission/torrent-add one), fallback only; failed
  attempts are rate limited
- phone pairing for TVs / tablets: the screen shows a QR code + short code, a signed-in phone scans
  it and approves the device for a day / a week / long-term (like "sign in with your phone" on TV apps)
Every device gets its own server-side session (sqlite), so /_devices can list and revoke them.
Cookies from the old stateless HMAC login (shared transmission account) stay valid until they
expire and are mapped onto OWNER.

Runs from /opt/stream-auth/venv (python3.11 + webauthn + segno). Bootstrap a passkey without the
password:  /opt/stream-auth/venv/bin/python /opt/stream-auth/stream-auth.py enroll <user>
New stream-only password:      ...stream-auth.py passwd <user>   (prints a generated passphrase once)
"""
import base64
import hashlib
import hmac
import html
import json
import os
import secrets
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import segno
from webauthn import (generate_authentication_options, generate_registration_options, options_to_json,
                      verify_authentication_response, verify_registration_response)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (AuthenticatorSelectionCriteria, PublicKeyCredentialDescriptor,
                                      ResidentKeyRequirement, UserVerificationRequirement)

HTPASSWD = os.environ.get("STREAM_AUTH_HTPASSWD", "/etc/stream-auth.htpasswd")   # stream-only accounts
OWNER = os.environ.get("STREAM_AUTH_OWNER", "danny")      # account that pre-passkey (legacy) cookies map to
KEYFILE = os.environ.get("STREAM_AUTH_KEY", "/etc/stream-auth.key")
DB = os.environ.get("STREAM_AUTH_DB", "/var/lib/stream-auth/auth.db")
ORIGIN = os.environ.get("STREAM_AUTH_ORIGIN", "https://stream.nellika.io")
RP_ID = os.environ.get("STREAM_AUTH_RP_ID", "nellika.io")
RP_NAME = "Nellika"
COOKIE = "stream_auth"
MAXAGE = 90 * 24 * 3600            # own sessions (passkey / password)
PORT = 8091
PAIR_TTL = 300                     # a QR / code is valid for 5 minutes
GRANTS = {"day": 86400, "week": 7 * 86400, "long": 90 * 86400}
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"   # no 0/O/1/I

with open(KEYFILE, "rb") as f:
    SECRET = f.read().strip()


def _b64e(b): return base64.urlsafe_b64encode(b).decode().rstrip("=")
def _b64d(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
def sha(s): return hashlib.sha256(s.encode()).hexdigest()
def now(): return int(time.time())


# ----------------------------------------------------------------------------- legacy cookies
def make_token(user):
    exp = now() + MAXAGE
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


# ----------------------------------------------------------------------------- storage
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (name TEXT PRIMARY KEY, handle TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS passkeys (id TEXT PRIMARY KEY, user TEXT NOT NULL, pubkey BLOB NOT NULL,
    sign_count INTEGER NOT NULL, label TEXT, created INTEGER, last_used INTEGER);
CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, user TEXT NOT NULL, kind TEXT, label TEXT,
    ua TEXT, ip TEXT, created INTEGER, expires INTEGER, last_seen INTEGER);
CREATE TABLE IF NOT EXISTS pairings (code TEXT PRIMARY KEY, poll TEXT NOT NULL, ua TEXT, ip TEXT,
    created INTEGER, expires INTEGER, state TEXT, user TEXT, label TEXT, grant_s INTEGER);
CREATE TABLE IF NOT EXISTS enroll (token TEXT PRIMARY KEY, user TEXT NOT NULL, expires INTEGER);
"""
_db_lock = threading.Lock()


def db_init():
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    with _db_lock, sqlite3.connect(DB) as con:
        con.executescript(SCHEMA)
    os.chmod(DB, 0o600)


def q(sql, args=()):
    with _db_lock:
        con = sqlite3.connect(DB, timeout=5)
        con.row_factory = sqlite3.Row
        try:
            with con:
                return [dict(r) for r in con.execute(sql, args).fetchall()]
        finally:
            con.close()


def one(sql, args=()):
    r = q(sql, args)
    return r[0] if r else None


def purge():
    t = now()
    q("DELETE FROM sessions WHERE expires < ?", (t,))
    q("DELETE FROM pairings WHERE expires < ?", (t - 3600,))
    q("DELETE FROM enroll WHERE expires < ?", (t,))
    for k in [k for k, v in list(CHALLENGES.items()) if v["expires"] < t]:
        CHALLENGES.pop(k, None)


def user_handle(user):
    row = one("SELECT handle FROM users WHERE name=?", (user,))
    if row:
        return row["handle"]
    h = bytes_to_base64url(secrets.token_bytes(32))
    q("INSERT OR IGNORE INTO users (name, handle) VALUES (?,?)", (user, h))
    return one("SELECT handle FROM users WHERE name=?", (user,))["handle"]


def ua_label(ua):
    """Short human name for a User-Agent, used as the default device label."""
    u = ua or ""
    for needle, name in (("Tizen", "Samsung TV"), ("Web0S", "LG TV"), ("webOS", "LG TV"), ("SMART-TV", "Smart TV"),
                         ("SmartTV", "Smart TV"), ("BRAVIA", "Sony TV"), ("AFT", "Fire TV"), ("CrKey", "Chromecast"),
                         ("Android TV", "Android TV"), ("iPad", "iPad"), ("iPhone", "iPhone")):
        if needle in u:
            return name
    if "Android" in u:
        return "Android tablet" if "Mobile" not in u else "Android phone"
    if "Macintosh" in u:
        return "Mac"
    if "Windows" in u:
        return "Windows PC"
    if "Linux" in u:
        return "Linux"
    return "Browser"


def new_session(user, kind, label, ua, ip, ttl=MAXAGE):
    """Create a session row; return the cookie value (only its hash is stored)."""
    token = secrets.token_urlsafe(32)
    t = now()
    q("INSERT INTO sessions (id,user,kind,label,ua,ip,created,expires,last_seen) VALUES (?,?,?,?,?,?,?,?,?)",
      (sha(token), user, kind, (label or ua_label(ua))[:60], (ua or "")[:300], ip, t, t + ttl, t))
    return "v2_" + token, ttl


def cookie_header(value, maxage):
    return "%s=%s; Path=/; Max-Age=%d; HttpOnly; Secure; SameSite=Lax" % (COOKIE, value, maxage)


# ----------------------------------------------------------------------------- password + rate limit
FAILS = {}   # ip -> [timestamps]


def too_many_fails(ip):
    t = time.time()
    FAILS[ip] = [x for x in FAILS.get(ip, []) if x > t - 900]
    return len(FAILS[ip]) >= 10


def valid_login(user, pw):
    if not user or "\n" in user or ":" in user or len(user) > 64 or not os.path.exists(HTPASSWD):
        return False
    try:
        r = subprocess.run(["htpasswd", "-vi", HTPASSWD, user], input=pw, text=True,
                           capture_output=True, timeout=5)
        return r.returncode == 0
    except Exception:
        return False


def safe_next(n):
    n = n or "/"
    return n if n.startswith("/") and not n.startswith("//") and "\\" not in n else "/"


# ----------------------------------------------------------------------------- webauthn
CHALLENGES = {}  # id -> {"kind", "challenge", "user", "enroll", "expires"}


def put_challenge(kind, challenge, user=None, enroll=None):
    cid = secrets.token_urlsafe(16)
    CHALLENGES[cid] = {"kind": kind, "challenge": challenge, "user": user, "enroll": enroll, "expires": now() + 300}
    return cid


def take_challenge(cid, kind):
    c = CHALLENGES.pop(cid or "", None)
    if not c or c["kind"] != kind or c["expires"] < now():
        raise ValueError("challenge expired, try again")
    return c


def register_options(user):
    existing = [PublicKeyCredentialDescriptor(id=base64url_to_bytes(r["id"]))
                for r in q("SELECT id FROM passkeys WHERE user=?", (user,))]
    opts = generate_registration_options(
        rp_id=RP_ID, rp_name=RP_NAME, user_id=base64url_to_bytes(user_handle(user)), user_name=user,
        user_display_name=user, exclude_credentials=existing,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED, user_verification=UserVerificationRequirement.PREFERRED))
    return opts


def credential_id(cred):
    return bytes_to_base64url(base64url_to_bytes(cred.get("rawId") or cred.get("id") or ""))


# ----------------------------------------------------------------------------- pages
CSS = """
:root{color-scheme:dark}
body{font-family:-apple-system,system-ui,sans-serif;background:#111;color:#eee;margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center}
main{display:flex;gap:22px;flex-wrap:wrap;justify-content:center;align-items:stretch;padding:24px 16px;max-width:980px}
.card{background:#1b1b1b;padding:24px;border-radius:16px;width:310px;max-width:88vw;box-sizing:border-box}
.wide{width:620px}
h1{font-size:20px;margin:0 0 4px}h2{font-size:16px;margin:18px 0 8px}p,.mut{color:#999;font-size:13px;margin:0 0 14px}
input,select{width:100%;box-sizing:border-box;padding:12px;margin:6px 0;border-radius:10px;border:1px solid #444;background:#222;color:#eee;font-size:16px}
button,.btn{display:block;width:100%;box-sizing:border-box;text-align:center;text-decoration:none;padding:13px;margin-top:12px;border:0;border-radius:10px;background:#4da3ff;color:#000;font-weight:600;font-size:16px;cursor:pointer}
button.sec,.btn.sec{background:#2a2a2a;color:#eee;border:1px solid #444}
button.danger{background:#5a1d1d;color:#fdd}
button.small{display:inline-block;width:auto;padding:7px 12px;margin:0;font-size:14px}
.err{color:#f66;font-size:13px;min-height:16px;margin-top:8px}
.ok{color:#7d7;font-size:14px}
details summary{cursor:pointer;color:#bbb;font-size:14px;margin-top:16px}
.qr{background:#fff;border-radius:12px;padding:12px;display:flex;justify-content:center}
.qr svg{width:100%;height:auto;max-width:260px}
.code{font:600 30px/1.2 ui-monospace,Menlo,monospace;letter-spacing:3px;text-align:center;margin:14px 0 6px}
.row{display:flex;gap:10px;align-items:center;justify-content:space-between;border-top:1px solid #2c2c2c;padding:10px 0}
.row .t{min-width:0}.row small{display:block;color:#999;font-size:12px}
.grants{display:flex;gap:8px}.grants label{flex:1;background:#222;border:1px solid #444;border-radius:10px;padding:10px 6px;text-align:center;font-size:14px;cursor:pointer}
.grants input{display:none}.grants input:checked+span{color:#4da3ff;font-weight:600}
a{color:#4da3ff}
"""

JS_COMMON = r"""
const b64u = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const unb64u = s => Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/') + '='.repeat((4 - s.length % 4) % 4)), c => c.charCodeAt(0));
const post = (p, body) => fetch(p, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body||{})})
  .then(async r => { const j = await r.json().catch(() => ({})); if (!r.ok && !j.error) j.error = 'HTTP ' + r.status; return j; });
const hasPasskeys = !!(window.PublicKeyCredential && navigator.credentials);
function credJSON(c) {
  const r = c.response, out = { id: c.id, rawId: b64u(c.rawId), type: c.type,
    clientExtensionResults: c.getClientExtensionResults ? c.getClientExtensionResults() : {},
    authenticatorAttachment: c.authenticatorAttachment || undefined, response: { clientDataJSON: b64u(r.clientDataJSON) } };
  if (r.attestationObject) { out.response.attestationObject = b64u(r.attestationObject);
    out.response.transports = r.getTransports ? r.getTransports() : []; }
  else { out.response.authenticatorData = b64u(r.authenticatorData); out.response.signature = b64u(r.signature);
    out.response.userHandle = r.userHandle ? b64u(r.userHandle) : null; }
  return out;
}
async function addPasskey(extra) {
  const b = await post('/_auth/passkey/register/begin', extra || {});
  if (b.error) throw new Error(b.error);
  const o = b.options;
  o.challenge = unb64u(o.challenge); o.user.id = unb64u(o.user.id);
  (o.excludeCredentials || []).forEach(c => c.id = unb64u(c.id));
  const cred = await navigator.credentials.create({ publicKey: o });
  const f = await post('/_auth/passkey/register/finish', Object.assign({ cid: b.cid, credential: credJSON(cred) }, extra || {}));
  if (f.error) throw new Error(f.error);
  return f;
}
async function passkeyLogin(next) {
  const b = await post('/_auth/passkey/login/begin');
  if (b.error) throw new Error(b.error);
  const o = b.options; o.challenge = unb64u(o.challenge);
  (o.allowCredentials || []).forEach(c => c.id = unb64u(c.id));
  const cred = await navigator.credentials.get({ publicKey: o });
  const f = await post('/_auth/passkey/login/finish', { cid: b.cid, credential: credJSON(cred), next });
  if (f.error) throw new Error(f.error);
  location.href = f.next || '/';
}
const ago = t => { const s = Math.max(0, Date.now()/1000 - t); return s < 90 ? 'just now' : s < 5400 ? Math.round(s/60) + ' min ago'
  : s < 129600 ? Math.round(s/3600) + ' h ago' : Math.round(s/86400) + ' days ago'; };
const esc = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
"""


def page(title, body, script=""):
    return ("""<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name=apple-mobile-web-app-capable content=yes><title>%s</title><style>%s</style></head>
<body>%s<script>%s
%s</script></body></html>""" % (html.escape(title), CSS, body, JS_COMMON, script)).encode()


def login_page(nxt, err=""):
    body = """<main>
<div class=card>
  <h1>Nellika Stream</h1><p>Sign in to watch your library.</p>
  <button id=pk style="display:none">Sign in with passkey</button>
  <div class=err id=pkerr></div>
  <details id=pw %s><summary>Use password</summary>
  <form method=post action=/_login accept-charset=utf-8>
    <input type=hidden name=next value="%s">
    <input name=username autocomplete=username autocapitalize=none autocorrect=off spellcheck=false placeholder=Username required>
    <input name=password type=password autocomplete=current-password placeholder=Password required>
    <div class=err>%s</div>
    <button type=submit class=sec>Sign in</button>
  </form></details>
</div>
<details class=card id=pairbox><summary style="margin:0;font-size:16px;color:#eee">On a TV or tablet? Sign in with your phone</summary>
  <p style="margin-top:12px">Scan with a phone that is signed in, or open <b>stream.nellika.io/_pair</b> there and type the code.</p>
  <div class=qr id=qr></div>
  <div class=code id=code>…</div>
  <div class=mut id=pstate style="text-align:center"></div>
</details>
</main>""" % ("open" if err else "", html.escape(nxt, quote=True), html.escape(err))
    script = """
const NEXT = %s;
if (hasPasskeys) { $pk = document.getElementById('pk'); $pk.style.display = '';
  $pk.onclick = () => passkeyLogin(NEXT).catch(e => { document.getElementById('pkerr').textContent = e.name === 'NotAllowedError' ? 'Cancelled.' : e.message; }); }
else document.getElementById('pw').open = true;
let pairTimer = null, pairPoll = null, pairExpires = 0;
async function startPair() {
  clearTimeout(pairTimer);
  const r = await post('/_auth/pair/start');
  if (r.error) { document.getElementById('pstate').textContent = r.error; return; }
  pairPoll = r.poll; pairExpires = Date.now() + r.expires_in * 1000;
  document.getElementById('qr').innerHTML = r.svg;
  document.getElementById('code').textContent = r.code;
  document.getElementById('pstate').textContent = 'Waiting for your phone…';
  poll();
}
async function poll() {
  if (!document.getElementById('pairbox').open) return;
  if (Date.now() > pairExpires) return startPair();
  const r = await post('/_auth/pair/poll', { poll: pairPoll }).catch(() => ({}));
  if (r.state === 'approved') { document.getElementById('pstate').textContent = 'Approved, opening…'; location.href = NEXT; return; }
  if (r.state === 'denied') { document.getElementById('pstate').textContent = 'Denied on the phone.'; return; }
  pairTimer = setTimeout(poll, 2000);
}
const box = document.getElementById('pairbox');
box.addEventListener('toggle', () => { if (box.open) startPair(); else clearTimeout(pairTimer); });
if (matchMedia('(min-width: 700px)').matches) box.open = true;   // TVs, tablets, laptops: show the QR straight away
""" % json.dumps(nxt)
    return page("Nellika Stream", body, script.replace("$pk", "window.pkBtn"))


def pair_page(code, pairing, user):
    if not code or not pairing:
        msg = "That code has expired or is wrong." if code else ""
        body = """<main><div class=card><h1>Sign in another screen</h1>
<p>Type the code shown on the TV or tablet.</p>
<form method=get action=/_pair><input name=c autocapitalize=characters autocomplete=off placeholder="ABC-DEF" required>
<div class=err>%s</div><button type=submit>Continue</button></form>
<a class="btn sec" href=/_devices>My devices</a></div></main>""" % html.escape(msg)
        return page("Sign in another screen", body)
    body = """<main><div class=card>
<h1>Allow this screen?</h1>
<p>Only allow it if <b>%s</b> is the code on the screen in front of you.</p>
<div class=mut>%s · %s · %s</div>
<label class=mut for=label style="display:block;margin-top:14px">Name</label>
<input id=label value="%s" maxlength=60>
<div class=mut style="margin:10px 0 6px">For how long</div>
<div class=grants>
 <label><input type=radio name=g value=day checked><span>Today</span></label>
 <label><input type=radio name=g value=week><span>1 week</span></label>
 <label><input type=radio name=g value=long><span>Long-term</span></label>
</div>
<button id=allow>Allow</button><button id=deny class=sec>Deny</button>
<div class=err id=err></div><div class=ok id=ok></div>
<p style="margin-top:14px">Signed in as %s. <a href=/_devices>My devices</a></p>
</div></main>""" % (html.escape(code_fmt(code)), html.escape(ua_label(pairing["ua"])), html.escape(pairing["ip"] or "?"),
                    "requested %ds ago" % max(0, now() - pairing["created"]),
                    html.escape(ua_label(pairing["ua"]), quote=True), html.escape(user))
    script = """
const CODE = %s;
async function answer(allow) {
  const g = document.querySelector('input[name=g]:checked').value;
  const r = await post('/_auth/pair/approve', { code: CODE, allow, grant: g, label: document.getElementById('label').value });
  if (r.error) { document.getElementById('err').textContent = r.error; return; }
  document.getElementById('allow').style.display = document.getElementById('deny').style.display = 'none';
  document.getElementById('ok').textContent = allow ? 'Done. The screen signs in within a few seconds.' : 'Denied.';
}
document.getElementById('allow').onclick = () => answer(true);
document.getElementById('deny').onclick = () => answer(false);
""" % json.dumps(code)
    return page("Allow this screen?", body, script)


def devices_page(user):
    body = """<main><div class="card wide">
<h1>My devices</h1><p>Signed in as <b>%s</b>. Revoke anything you don't recognise.</p>
<h2>Signed-in screens</h2><div id=sessions class=mut>Loading…</div>
<h2>Passkeys</h2><div id=passkeys class=mut></div>
<button id=add class=sec style="display:none">Add a passkey on this device</button>
<div class=err id=err></div><div class=ok id=ok></div>
<h2>Sign in a TV or tablet</h2>
<p>Open <b>stream.nellika.io</b> on it, then scan its QR code with this phone, or type its code here:</p>
<form method=get action=/_pair style="display:flex;gap:8px"><input name=c autocapitalize=characters autocomplete=off placeholder="ABC-DEF" required>
<button type=submit class=small>Go</button></form>
<a class="btn sec" href=/>Back to the library</a>
<a class="btn sec" href=/_logout>Sign out this device</a>
</div></main>""" % html.escape(user)
    script = """
const KIND = { passkey: 'passkey', password: 'password', paired: 'paired by phone', enroll: 'passkey setup' };
async function load() {
  const r = await fetch('/_auth/devices').then(r => r.json());
  document.getElementById('sessions').innerHTML = r.sessions.map(s => `<div class=row><div class=t>${esc(s.label)}${s.current ? ' <b>(this device)</b>' : ''}
    <small>${esc(KIND[s.kind] || s.kind)} · last used ${ago(s.last_seen)} · ${esc(s.ip || '')} · until ${new Date(s.expires*1000).toLocaleDateString()}</small></div>
    ${s.current ? '' : `<button class="small danger" data-s="${s.id}">Revoke</button>`}</div>`).join('') || 'None';
  document.getElementById('passkeys').innerHTML = r.passkeys.map(p => `<div class=row><div class=t>${esc(p.label)}
    <small>added ${ago(p.created)}${p.last_used ? ' · used ' + ago(p.last_used) : ''}</small></div>
    <button class="small danger" data-p="${p.id}">Remove</button></div>`).join('') || 'No passkeys yet: add one so you never need the password.';
  document.querySelectorAll('[data-s]').forEach(b => b.onclick = async () => { await post('/_auth/session/revoke', { id: b.dataset.s }); load(); });
  document.querySelectorAll('[data-p]').forEach(b => b.onclick = async () => {
    if (!confirm('Remove this passkey? That device will need another way to sign in.')) return;
    await post('/_auth/passkey/delete', { id: b.dataset.p }); load(); });
}
if (hasPasskeys) { const a = document.getElementById('add'); a.style.display = '';
  a.onclick = () => addPasskey().then(() => { document.getElementById('ok').textContent = 'Passkey added.'; load(); })
    .catch(e => { document.getElementById('err').textContent = e.name === 'NotAllowedError' ? 'Cancelled.' : e.message; }); }
load();
"""
    return page("My devices", body, script)


def enroll_page(token, user):
    if not user:
        return page("Passkey setup", "<main><div class=card><h1>Link expired</h1><p>Ask for a new setup link.</p></div></main>")
    body = """<main><div class=card><h1>Set up your passkey</h1>
<p>Account <b>%s</b>. Your phone stores the passkey (Face ID / fingerprint); from then on you sign in without a password, on every device in your iCloud / Google account.</p>
<button id=go>Create passkey</button><div class=err id=err></div></div></main>""" % html.escape(user)
    script = """
const T = %s;
document.getElementById('go').onclick = () => (hasPasskeys ? addPasskey({ enroll: T }) : Promise.reject(new Error('This browser has no passkey support.')))
  .then(() => { location.href = '/_devices'; })
  .catch(e => { document.getElementById('err').textContent = e.name === 'NotAllowedError' ? 'Cancelled.' : e.message; });
""" % json.dumps(token)
    return page("Passkey setup", body, script)


def code_fmt(code):
    return "%s-%s" % (code[:3], code[3:])


def norm_code(c):
    return "".join(ch for ch in (c or "").upper() if ch in CODE_ALPHABET)[:6]


# ----------------------------------------------------------------------------- http
class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    # --- plumbing
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

    def _json(self, obj, code=200, extra=None):
        return self._send(code, json.dumps(obj).encode(), "application/json", extra)

    def _redirect(self, loc, extra=None):
        return self._send(302, b"", extra=[("Location", loc)] + (extra or []))

    def ip(self):
        return self.headers.get("X-Real-IP") or self.client_address[0]

    def ua(self):
        return self.headers.get("User-Agent", "")

    def _cookie(self):
        for part in self.headers.get("Cookie", "").split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                if k == COOKIE:
                    return v
        return None

    def session(self):
        """{"user", "sid", "kind"} for the request's cookie, or None. Legacy cookies have sid None."""
        v = self._cookie()
        if not v:
            return None
        if v.startswith("v2_"):
            sid = sha(v[3:])
            row = one("SELECT * FROM sessions WHERE id=? AND expires>?", (sid, now()))
            if not row:
                return None
            if now() - (row["last_seen"] or 0) > 60:
                q("UPDATE sessions SET last_seen=?, ip=? WHERE id=?", (now(), self.ip(), sid))
            return {"user": row["user"], "sid": sid, "kind": row["kind"]}
        return {"user": OWNER, "sid": None, "kind": "legacy"} if check_token(v) else None

    def upgrade_legacy(self, s):
        """Turn an old stateless cookie into a listed, revocable session (pages only)."""
        if s and s["sid"] is None:
            value, ttl = new_session(s["user"], "password", None, self.ua(), self.ip())
            s["sid"] = sha(value[3:])
            return [("Set-Cookie", cookie_header(value, ttl))]
        return []

    def body_json(self):
        if not self.headers.get("Content-Type", "").startswith("application/json"):
            raise PermissionError("bad content type")
        origin = self.headers.get("Origin")
        if origin and origin != ORIGIN:   # CSRF: same-origin fetches only
            raise PermissionError("bad origin")
        n = int(self.headers.get("Content-Length") or 0)
        if n > 64 * 1024:
            raise ValueError("request too large")
        return json.loads(self.rfile.read(n).decode() or "{}") if n else {}

    # --- GET
    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        path, qs = u.path, urllib.parse.parse_qs(u.query)
        arg = lambda k: (qs.get(k) or [""])[0]
        if path == "/_authcheck":
            s = self.session()
            return self._send(200 if s else 401, b"", extra=[("X-Auth-User", s["user"])] if s else None)
        if path == "/_logout":
            s = self.session()
            if s and s["sid"]:
                q("DELETE FROM sessions WHERE id=?", (s["sid"],))
            return self._redirect("/_login", [("Set-Cookie", cookie_header("", 0))])
        if path == "/_login":
            return self._send(200, login_page(safe_next(arg("next"))))
        if path == "/_enroll":
            row = one("SELECT user FROM enroll WHERE token=? AND expires>?", (sha(arg("t")), now()))
            return self._send(200, enroll_page(arg("t"), row["user"] if row else None))
        s = self.session()
        if path in ("/_pair", "/_devices", "/_auth/devices") and not s:
            if path == "/_auth/devices":
                return self._json({"error": "sign in first"}, 401)
            return self._redirect("/_login?next=" + urllib.parse.quote(self.path, safe=""))
        if path == "/_pair":
            code = norm_code(arg("c"))
            pairing = one("SELECT * FROM pairings WHERE code=? AND state='pending' AND expires>?", (code, now())) if code else None
            return self._send(200, pair_page(code, pairing, s["user"]), extra=self.upgrade_legacy(s))
        if path == "/_devices":
            return self._send(200, devices_page(s["user"]), extra=self.upgrade_legacy(s))
        if path == "/_auth/devices":
            sessions = q("SELECT id,kind,label,ip,created,expires,last_seen FROM sessions WHERE user=? AND expires>? "
                         "ORDER BY last_seen DESC", (s["user"], now()))
            for x in sessions:
                x["current"] = x["id"] == s["sid"]
            passkeys = q("SELECT id,label,created,last_used FROM passkeys WHERE user=? ORDER BY created", (s["user"],))
            return self._json({"user": s["user"], "sessions": sessions, "passkeys": passkeys})
        return self._send(404, b"not found")

    # --- POST
    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        try:
            if path == "/_login":
                return self.password_login()
            body = self.body_json()
            fn = self.API.get(path)
            if not fn:
                return self._json({"error": "not found"}, 404)
            return fn(self, body)
        except PermissionError as e:
            return self._json({"error": str(e)}, 403)
        except Exception as e:
            return self._json({"error": str(e)}, 400)

    def password_login(self):
        n = int(self.headers.get("Content-Length") or 0)
        data = urllib.parse.parse_qs(self.rfile.read(min(n, 8192)).decode("utf-8", "replace"))
        user = (data.get("username") or [""])[0].strip()
        pw = (data.get("password") or [""])[0]
        nxt = safe_next((data.get("next") or ["/"])[0])
        if too_many_fails(self.ip()):
            return self._send(429, login_page(nxt, "Too many attempts, try again in 15 minutes."))
        if valid_login(user, pw):
            value, ttl = new_session(user, "password", None, self.ua(), self.ip())
            return self._redirect(nxt, [("Set-Cookie", cookie_header(value, ttl))])
        FAILS.setdefault(self.ip(), []).append(time.time())
        return self._send(401, login_page(nxt, "Wrong username or password."))

    # passkeys -------------------------------------------------------------
    def api_register_begin(self, body):
        enroll = body.get("enroll")
        if enroll:
            row = one("SELECT user FROM enroll WHERE token=? AND expires>?", (sha(enroll), now()))
            if not row:
                raise PermissionError("setup link expired")
            user = row["user"]
        else:
            s = self.session()
            if not s:
                raise PermissionError("sign in first")
            user = s["user"]
        opts = register_options(user)
        cid = put_challenge("register", opts.challenge, user, enroll)
        return self._json({"cid": cid, "options": json.loads(options_to_json(opts))})

    def api_register_finish(self, body):
        c = take_challenge(body.get("cid"), "register")
        if c["enroll"]:
            if not one("SELECT 1 AS x FROM enroll WHERE token=? AND expires>?", (sha(c["enroll"]), now())):
                raise PermissionError("setup link expired")
        else:
            s = self.session()
            if not s or s["user"] != c["user"]:
                raise PermissionError("sign in first")
        v = verify_registration_response(credential=body["credential"], expected_challenge=c["challenge"],
                                         expected_rp_id=RP_ID, expected_origin=ORIGIN, require_user_verification=False)
        label = (body.get("label") or ua_label(self.ua()))[:60]
        q("INSERT INTO passkeys (id,user,pubkey,sign_count,label,created,last_used) VALUES (?,?,?,?,?,?,NULL)",
          (bytes_to_base64url(v.credential_id), c["user"], v.credential_public_key, v.sign_count, label, now()))
        extra = []
        if c["enroll"]:
            q("DELETE FROM enroll WHERE token=?", (sha(c["enroll"]),))
            value, ttl = new_session(c["user"], "passkey", None, self.ua(), self.ip())
            extra = [("Set-Cookie", cookie_header(value, ttl))]
        return self._json({"ok": True}, extra=extra)

    def api_login_begin(self, body):
        opts = generate_authentication_options(rp_id=RP_ID, user_verification=UserVerificationRequirement.PREFERRED)
        cid = put_challenge("login", opts.challenge)
        return self._json({"cid": cid, "options": json.loads(options_to_json(opts))})

    def api_login_finish(self, body):
        c = take_challenge(body.get("cid"), "login")
        cred = body["credential"]
        row = one("SELECT * FROM passkeys WHERE id=?", (credential_id(cred),))
        if not row:
            raise PermissionError("unknown passkey (removed?)")
        handle = (cred.get("response") or {}).get("userHandle")
        if handle and handle != user_handle(row["user"]):
            raise PermissionError("passkey does not match its account")
        v = verify_authentication_response(credential=cred, expected_challenge=c["challenge"], expected_rp_id=RP_ID,
                                           expected_origin=ORIGIN, credential_public_key=row["pubkey"],
                                           credential_current_sign_count=row["sign_count"],
                                           require_user_verification=False)
        q("UPDATE passkeys SET sign_count=?, last_used=? WHERE id=?", (v.new_sign_count, now(), row["id"]))
        value, ttl = new_session(row["user"], "passkey", None, self.ua(), self.ip())
        return self._json({"ok": True, "next": safe_next(body.get("next"))},
                          extra=[("Set-Cookie", cookie_header(value, ttl))])

    def api_passkey_delete(self, body):
        s = self.session()
        if not s:
            raise PermissionError("sign in first")
        q("DELETE FROM passkeys WHERE id=? AND user=?", (str(body.get("id")), s["user"]))
        return self._json({"ok": True})

    # phone pairing ---------------------------------------------------------
    def api_pair_start(self, body):
        t = now()
        if one("SELECT count(*) AS n FROM pairings WHERE ip=? AND state='pending' AND expires>?", (self.ip(), t))["n"] >= 6 \
                or one("SELECT count(*) AS n FROM pairings WHERE expires>?", (t,))["n"] >= 300:
            return self._json({"error": "too many pending codes, wait a few minutes"}, 429)
        poll = secrets.token_urlsafe(24)
        for _ in range(10):
            code = "".join(secrets.choice(CODE_ALPHABET) for _ in range(6))
            try:
                q("INSERT INTO pairings (code,poll,ua,ip,created,expires,state) VALUES (?,?,?,?,?,?,'pending')",
                  (code, sha(poll), self.ua()[:300], self.ip(), t, t + PAIR_TTL))
                break
            except sqlite3.IntegrityError:
                continue
        url = "%s/_pair?c=%s" % (ORIGIN, code)
        svg = segno.make(url, error="m").svg_inline(scale=6, border=2, dark="#000", light="#fff")
        return self._json({"code": code_fmt(code), "poll": poll, "url": url, "svg": svg, "expires_in": PAIR_TTL})

    def api_pair_poll(self, body):
        row = one("SELECT * FROM pairings WHERE poll=?", (sha(str(body.get("poll"))),))
        if not row or (row["state"] == "pending" and row["expires"] < now()):
            return self._json({"state": "expired"})
        if row["state"] == "approved":
            # one-time hand-over: the session cookie goes to the screen that holds the poll secret
            q("UPDATE pairings SET state='used' WHERE code=? AND state='approved'", (row["code"],))
            value, ttl = new_session(row["user"], "paired", row["label"], row["ua"], self.ip(), row["grant_s"])
            return self._json({"state": "approved"}, extra=[("Set-Cookie", cookie_header(value, ttl))])
        return self._json({"state": "pending" if row["state"] == "pending" else row["state"]})

    def api_pair_approve(self, body):
        s = self.session()
        if not s:
            raise PermissionError("sign in first")
        code = norm_code(body.get("code"))
        row = one("SELECT * FROM pairings WHERE code=? AND state='pending' AND expires>?", (code, now()))
        if not row:
            raise ValueError("that code has expired, ask the screen for a new one")
        if body.get("allow"):
            grant = GRANTS.get(body.get("grant"), GRANTS["day"])
            label = (str(body.get("label") or "") or ua_label(row["ua"]))[:60]
            q("UPDATE pairings SET state='approved', user=?, label=?, grant_s=? WHERE code=?",
              (s["user"], label, grant, code))
        else:
            q("UPDATE pairings SET state='denied' WHERE code=?", (code,))
        return self._json({"ok": True})

    def api_session_revoke(self, body):
        s = self.session()
        if not s:
            raise PermissionError("sign in first")
        q("DELETE FROM sessions WHERE id=? AND user=?", (str(body.get("id")), s["user"]))
        return self._json({"ok": True})

    API = {
        "/_auth/passkey/register/begin": api_register_begin,
        "/_auth/passkey/register/finish": api_register_finish,
        "/_auth/passkey/login/begin": api_login_begin,
        "/_auth/passkey/login/finish": api_login_finish,
        "/_auth/passkey/delete": api_passkey_delete,
        "/_auth/pair/start": api_pair_start,
        "/_auth/pair/poll": api_pair_poll,
        "/_auth/pair/approve": api_pair_approve,
        "/_auth/session/revoke": api_session_revoke,
    }


def set_password(user):
    """Generate a passphrase for a stream-only account (bcrypt in HTPASSWD) and return it."""
    words = [secrets.token_hex(2) for _ in range(4)]
    pw = "-".join(words)
    args = ["htpasswd", "-iB"] + ([] if os.path.exists(HTPASSWD) else ["-c"]) + [HTPASSWD, user]
    subprocess.run(args, input=pw, text=True, capture_output=True, timeout=10, check=True)
    os.chmod(HTPASSWD, 0o640)
    return pw


def enroll_link(user, hours=24):
    token = secrets.token_urlsafe(24)
    q("INSERT INTO enroll (token, user, expires) VALUES (?,?,?)", (sha(token), user, now() + hours * 3600))
    return "%s/_enroll?t=%s" % (ORIGIN, token)


def janitor():
    while True:
        try:
            purge()
        except Exception as e:
            print("purge failed: %r" % e, file=sys.stderr, flush=True)
        time.sleep(600)


if __name__ == "__main__":
    db_init()
    if len(sys.argv) == 3 and sys.argv[1] == "enroll":
        print(enroll_link(sys.argv[2]))
        sys.exit(0)
    if len(sys.argv) == 3 and sys.argv[1] == "passwd":
        print(set_password(sys.argv[2]))
        sys.exit(0)
    threading.Thread(target=janitor, daemon=True).start()
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
