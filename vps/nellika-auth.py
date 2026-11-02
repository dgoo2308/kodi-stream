#!/usr/bin/env python3
"""nellika-auth: one sign-in (identity) service for every Nellika web app proxied through nell_remote.

It answers WHO someone is; each app decides WHAT they may do (nginx hands the app trusted
X-Auth-User / X-Auth-Name / X-Auth-Admin headers).

Hosts
- auth.nellika.io: the sign-in pages and the JSON API. Ways in: passkey (WebAuthn, rp id nellika.io),
  a TV / tablet approved from a signed-in phone (QR + short code), and a password fallback (htpasswd,
  owner only, rate limited). Accounts are invite-only: an admin makes an invite link / QR, the person
  creates a passkey with it. Admins manage people at /users; everyone manages their devices at /devices.
- any app host (*.nellika.io behind nell_remote, see snippets/): /_authcheck (nginx auth_request),
  /_auth/start (nginx sends signed-out visitors here -> auth host), /_auth/callback (single-use code ->
  the app's OWN host-only cookie), /_auth/logout, /_auth/me. No cookie is shared between hosts: a
  *.nellika.io cookie would also reach sites that are not behind nell_remote.

Single sign-on: the app sends a signed-out browser to auth.nellika.io/authorize?rd=<url>; with a valid
sign-in there it gets a 60 s single-use code bound to that app host, the app trades it for its own
session (never longer-lived than the sign-in it came from, so a TV approved "for today" stays today).

Every session is a server-side row (only the token hash is stored), so revoking a device or disabling
a person takes effect on the next request. Old stream.nellika.io cookies keep working.

Runs from /opt/nellika-auth/venv (python3.11 + webauthn + segno), 127.0.0.1:8091.
CLI: nellika-auth.py enroll <user> | passwd <user> | invite [note] | adduser <name> [admin]
"""
import base64
import hashlib
import hmac
import html
import json
import os
import re
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

ENV = os.environ.get
HTPASSWD = ENV("NAUTH_HTPASSWD", "/etc/stream-auth.htpasswd")       # password fallback (owner)
OWNER = ENV("NAUTH_OWNER", "danny")                                   # first admin; legacy cookies map here
KEYFILE = ENV("NAUTH_KEY", "/etc/stream-auth.key")                    # only for legacy HMAC cookies
DB = ENV("NAUTH_DB", "/var/lib/nellika-auth/auth.db")
AUTH_HOST = ENV("NAUTH_HOST", "auth.nellika.io")
AUTH_ORIGIN = "https://" + AUTH_HOST
RP_ID = ENV("NAUTH_RP_ID", "nellika.io")
RP_NAME = "Nellika"
APP_SUFFIXES = tuple(x.strip() for x in ENV("NAUTH_APP_SUFFIXES", ".nellika.io").split(",") if x.strip())
LEGACY_HOST = ENV("NAUTH_LEGACY_HOST", "stream.nellika.io")         # host of the old stream-auth cookies
LEGACY_COOKIE = "stream_auth"
COOKIE = "nauth"
MAXAGE = 90 * 24 * 3600
PORT = int(ENV("NAUTH_PORT", "8091"))
PAIR_TTL = 300
CODE_TTL = 60
INVITE_TTL = 7 * 86400
GRANTS = {"day": 86400, "week": 7 * 86400, "long": 90 * 86400}
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,31}$")
HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")

try:
    with open(KEYFILE, "rb") as f:
        SECRET = f.read().strip()
except OSError:
    SECRET = b""


def _b64e(b): return base64.urlsafe_b64encode(b).decode().rstrip("=")
def _b64d(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
def sha(s): return hashlib.sha256(s.encode()).hexdigest()
def now(): return int(time.time())


def check_legacy_token(tok):
    """Stateless HMAC cookie of the first stream login (user|exp signed) -> True while valid."""
    if not SECRET:
        return False
    try:
        body, mac = tok.split(".", 1)
        msg = _b64d(body)
        if not hmac.compare_digest(_b64d(mac), hmac.new(SECRET, msg, hashlib.sha256).digest()):
            return False
        return int(msg.decode().split("|")[1]) > time.time()
    except Exception:
        return False


def app_host_ok(host):
    """Hosts that may receive sign-ins: our app domains, never the auth host itself."""
    host = (host or "").lower()
    return bool(HOST_RE.match(host)) and host != AUTH_HOST and any(host.endswith(s) for s in APP_SUFFIXES)


def local_path(p, default="/"):
    p = p or default
    # must be a site-local path and carry no control chars: a raw CR/LF reaching a Location
    # header would allow HTTP response splitting (Python's send_header does not reject it).
    if not (p.startswith("/") and not p.startswith("//") and "\\" not in p):
        return default
    return default if any(ord(c) < 0x20 or ord(c) == 0x7f for c in p) else p


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
CREATE TABLE IF NOT EXISTS invites (token TEXT PRIMARY KEY, created_by TEXT, note TEXT, created INTEGER,
    expires INTEGER, used_by TEXT, used_at INTEGER);
CREATE TABLE IF NOT EXISTS codes (code TEXT PRIMARY KEY, user TEXT NOT NULL, app TEXT NOT NULL, rd TEXT,
    expires INTEGER, session_expires INTEGER, label TEXT);
"""
ADD_COLUMNS = {
    "users": [("display", "TEXT"), ("admin", "INTEGER DEFAULT 0"), ("disabled", "INTEGER DEFAULT 0"),
              ("created", "INTEGER"), ("invited_by", "TEXT")],
    "sessions": [("app", "TEXT")],
}
_db_lock = threading.RLock()


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


def db_init():
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    with _db_lock, sqlite3.connect(DB) as con:
        con.executescript(SCHEMA)
        for table, cols in ADD_COLUMNS.items():
            have = {r[1] for r in con.execute("PRAGMA table_info(%s)" % table)}
            for col, typ in cols:
                if col not in have:
                    con.execute("ALTER TABLE %s ADD COLUMN %s %s" % (table, col, typ))
        # sessions from the stream-only service belonged to stream.nellika.io
        con.execute("UPDATE sessions SET app=? WHERE app IS NULL", (LEGACY_HOST,))
    os.chmod(DB, 0o600)
    ensure_user(OWNER, admin=True)


def ensure_user(name, admin=False, display=None, invited_by=None):
    row = one("SELECT * FROM users WHERE name=?", (name,))
    if not row:
        q("INSERT OR IGNORE INTO users (name, handle, display, admin, disabled, created, invited_by) VALUES (?,?,?,?,0,?,?)",
          (name, bytes_to_base64url(secrets.token_bytes(32)), display or name, 1 if admin else 0, now(), invited_by))
    elif admin and not row.get("admin"):
        q("UPDATE users SET admin=1 WHERE name=?", (name,))
    return one("SELECT * FROM users WHERE name=?", (name,))


def user_row(name):
    return one("SELECT * FROM users WHERE name=?", (name,)) if name else None


def active_user(name):
    u = user_row(name)
    return u if u and not u.get("disabled") else None


def purge():
    t = now()
    q("DELETE FROM sessions WHERE expires < ?", (t,))
    q("DELETE FROM pairings WHERE expires < ?", (t - 3600,))
    q("DELETE FROM enroll WHERE expires < ?", (t,))
    q("DELETE FROM codes WHERE expires < ?", (t,))
    q("DELETE FROM invites WHERE expires < ? AND used_by IS NULL", (t - 30 * 86400,))
    for k in [k for k, v in list(CHALLENGES.items()) if v["expires"] < t]:
        CHALLENGES.pop(k, None)


def ua_label(ua):
    u = ua or ""
    for needle, name in (("Tizen", "Samsung TV"), ("Web0S", "LG TV"), ("webOS", "LG TV"), ("NetCast", "LG TV"),
                         ("SMART-TV", "Smart TV"), ("SmartTV", "Smart TV"), ("BRAVIA", "Sony TV"), ("AFT", "Fire TV"),
                         ("CrKey", "Chromecast"), ("Android TV", "Android TV"), ("iPad", "iPad"), ("iPhone", "iPhone")):
        if needle in u:
            return name
    if "Android" in u:
        return "Android tablet" if "Mobile" not in u else "Android phone"
    for needle, name in (("Macintosh", "Mac"), ("Windows", "Windows PC"), ("Linux", "Linux")):
        if needle in u:
            return name
    return "Browser"


def new_session(user, kind, label, ua, ip, app, ttl=MAXAGE):
    """Session row for `app` (host); returns (cookie value, max-age). Only the token hash is stored."""
    token = secrets.token_urlsafe(32)
    t = now()
    q("INSERT INTO sessions (id,user,kind,label,ua,ip,created,expires,last_seen,app) VALUES (?,?,?,?,?,?,?,?,?,?)",
      (sha(token), user, kind, (label or ua_label(ua))[:60], (ua or "")[:300], ip, t, t + int(ttl), t, app))
    return "v2_" + token, int(ttl)


def cookie_header(name, value, maxage):
    return "%s=%s; Path=/; Max-Age=%d; HttpOnly; Secure; SameSite=Lax" % (name, value, maxage)


# ----------------------------------------------------------------------------- password + rate limit
FAILS = {}


def too_many_fails(ip):
    t = time.time()
    FAILS[ip] = [x for x in FAILS.get(ip, []) if x > t - 900]
    return len(FAILS[ip]) >= 10


def valid_login(user, pw):
    if not user or "\n" in user or ":" in user or len(user) > 64 or not os.path.exists(HTPASSWD):
        return False
    try:
        r = subprocess.run(["htpasswd", "-vi", HTPASSWD, user], input=pw, text=True, capture_output=True, timeout=5)
        return r.returncode == 0
    except Exception:
        return False


# ----------------------------------------------------------------------------- webauthn
CHALLENGES = {}


def put_challenge(kind, challenge, **data):
    cid = secrets.token_urlsafe(16)
    CHALLENGES[cid] = dict(data, kind=kind, challenge=challenge, expires=now() + 300)
    return cid


def take_challenge(cid, kind):
    c = CHALLENGES.pop(cid or "", None)
    if not c or c["kind"] != kind or c["expires"] < now():
        raise ValueError("challenge expired, try again")
    return c


def register_options(name, handle, display):
    existing = [PublicKeyCredentialDescriptor(id=base64url_to_bytes(r["id"]))
                for r in q("SELECT id FROM passkeys WHERE user=?", (name,))]
    return generate_registration_options(
        rp_id=RP_ID, rp_name=RP_NAME, user_id=base64url_to_bytes(handle), user_name=name,
        user_display_name=display or name, exclude_credentials=existing,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED, user_verification=UserVerificationRequirement.PREFERRED))


def credential_id(cred):
    return bytes_to_base64url(base64url_to_bytes(cred.get("rawId") or cred.get("id") or ""))


def code_fmt(code):
    return "%s-%s" % (code[:3], code[3:])


def norm_code(c):
    return "".join(ch for ch in (c or "").upper() if ch in CODE_ALPHABET)[:6]


def qr_svg(url):
    return segno.make(url, error="m").svg_inline(scale=6, border=2, dark="#000", light="#fff")


# ----------------------------------------------------------------------------- pages
CSS = """
:root{color-scheme:dark}
body{font-family:-apple-system,system-ui,sans-serif;background:#111;color:#eee;margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center}
main{display:flex;gap:22px;flex-wrap:wrap;justify-content:center;align-items:stretch;padding:24px 16px;max-width:980px}
.card{background:#1b1b1b;padding:24px;border-radius:16px;width:310px;max-width:88vw;box-sizing:border-box}
.wide{width:680px}
h1{font-size:20px;margin:0 0 4px}h2{font-size:16px;margin:18px 0 8px}p,.mut{color:#999;font-size:13px;margin:0 0 14px}
input,select{width:100%;box-sizing:border-box;padding:12px;margin:6px 0;border-radius:10px;border:1px solid #444;background:#222;color:#eee;font-size:16px}
button,.btn{display:block;width:100%;box-sizing:border-box;text-align:center;text-decoration:none;padding:13px;margin-top:12px;border:0;border-radius:10px;background:#4da3ff;color:#000;font-weight:600;font-size:16px;cursor:pointer}
button.sec,.btn.sec{background:#2a2a2a;color:#eee;border:1px solid #444}
button.danger{background:#5a1d1d;color:#fdd}
button.small{display:inline-block;width:auto;padding:7px 12px;margin:0 0 0 6px;font-size:14px}
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
.tag{display:inline-block;font-size:11px;padding:1px 6px;border-radius:6px;background:#2a2a2a;color:#bbb;margin-left:6px}
.link{word-break:break-all;background:#222;border-radius:8px;padding:8px;font-size:13px}
a{color:#4da3ff}
"""

JS_COMMON = r"""
const b64u = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const unb64u = s => Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/') + '='.repeat((4 - s.length % 4) % 4)), c => c.charCodeAt(0));
const post = (p, body) => fetch(p, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body||{})})
  .then(async r => { const j = await r.json().catch(() => ({})); if (!r.ok && !j.error) j.error = 'HTTP ' + r.status; return j; });
const $id = id => document.getElementById(id);
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
async function createPasskey(beginBody) {
  const b = await post('/_auth/passkey/register/begin', beginBody || {});
  if (b.error) throw new Error(b.error);
  const o = b.options;
  o.challenge = unb64u(o.challenge); o.user.id = unb64u(o.user.id);
  (o.excludeCredentials || []).forEach(c => c.id = unb64u(c.id));
  const cred = await navigator.credentials.create({ publicKey: o });
  const f = await post('/_auth/passkey/register/finish', { cid: b.cid, credential: credJSON(cred) });
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
const why = e => e && e.name === 'NotAllowedError' ? 'Cancelled.' : (e && e.message) || String(e);
const ago = t => { if (!t) return 'never'; const s = Math.max(0, Date.now()/1000 - t); return s < 90 ? 'just now' : s < 5400 ? Math.round(s/60) + ' min ago'
  : s < 129600 ? Math.round(s/3600) + ' h ago' : Math.round(s/86400) + ' days ago'; };
const esc = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
"""


def page(title, body, script=""):
    return ("""<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name=apple-mobile-web-app-capable content=yes><title>%s</title><style>%s</style></head>
<body>%s<script>%s
%s</script></body></html>""" % (html.escape(title), CSS, body, JS_COMMON, script)).encode()


def app_name(next_path):
    """'stream.nellika.io' when the sign-in was started by that app (next = /authorize?rd=...)."""
    try:
        rd = urllib.parse.parse_qs(urllib.parse.urlparse(next_path).query).get("rd", [""])[0]
        host = urllib.parse.urlparse(rd).hostname or ""
        return host if app_host_ok(host) else ""
    except Exception:
        return ""


def login_page(nxt, err=""):
    app = app_name(nxt)
    body = """<main>
<div class=card>
  <h1>Sign in to Nellika</h1><p>%s</p>
  <button id=pk style="display:none">Sign in with passkey</button>
  <div class=err id=pkerr></div>
  <details id=pw %s><summary>Use password</summary>
  <form method=post action=/login accept-charset=utf-8>
    <input type=hidden name=next value="%s">
    <input name=username autocomplete=username autocapitalize=none autocorrect=off spellcheck=false placeholder=Username required>
    <input name=password type=password autocomplete=current-password placeholder=Password required>
    <div class=err>%s</div>
    <button type=submit class=sec>Sign in</button>
  </form></details>
</div>
<details class=card id=pairbox><summary style="margin:0;font-size:16px;color:#eee">On a TV or tablet? Sign in with your phone</summary>
  <p style="margin-top:12px">Scan with a phone that is signed in, or open <b>%s/pair</b> there and type the code.</p>
  <div class=qr id=qr></div>
  <div class=code id=code>…</div>
  <div class=mut id=pstate style="text-align:center"></div>
</details>
</main>""" % (("to continue to <b>%s</b>." % html.escape(app)) if app else "One sign-in for the Nellika apps.",
              "open" if err else "", html.escape(nxt, quote=True), html.escape(err), AUTH_HOST)
    script = """
const NEXT = %s;
if (hasPasskeys) { const pk = $id('pk'); pk.style.display = '';
  pk.onclick = () => passkeyLogin(NEXT).catch(e => { $id('pkerr').textContent = why(e); }); }
else $id('pw').open = true;
let pairTimer = null, pairPoll = null, pairExpires = 0;
async function startPair() {
  clearTimeout(pairTimer);
  const r = await post('/_auth/pair/start');
  if (r.error) { $id('pstate').textContent = r.error; return; }
  pairPoll = r.poll; pairExpires = Date.now() + r.expires_in * 1000;
  $id('qr').innerHTML = r.svg; $id('code').textContent = r.code; $id('pstate').textContent = 'Waiting for your phone…';
  poll();
}
async function poll() {
  if (!$id('pairbox').open) return;
  if (Date.now() > pairExpires) return startPair();
  const r = await post('/_auth/pair/poll', { poll: pairPoll }).catch(() => ({}));
  if (r.state === 'approved') { $id('pstate').textContent = 'Approved, opening…'; location.href = NEXT; return; }
  if (r.state === 'denied') { $id('pstate').textContent = 'Denied on the phone.'; return; }
  pairTimer = setTimeout(poll, 2000);
}
const box = $id('pairbox');
box.addEventListener('toggle', () => { if (box.open) startPair(); else clearTimeout(pairTimer); });
if (matchMedia('(min-width: 700px)').matches) box.open = true;
""" % json.dumps(nxt)
    return page("Sign in · Nellika", body, script)


def home_page(u):
    admin = '<a class="btn sec" href=/users>People and invites</a>' if u.get("admin") else ""
    body = """<main><div class=card><h1>Nellika</h1><p>Signed in as <b>%s</b> (%s).</p>
<a class="btn sec" href=/devices>My devices and passkeys</a>%s
<a class="btn sec" href=/logout>Sign out of this browser</a></div></main>""" % (
        html.escape(u.get("display") or u["name"]), html.escape(u["name"]), admin)
    return page("Nellika", body)


def pair_page(code, pairing, user):
    if not code or not pairing:
        msg = "That code has expired or is wrong." if code else ""
        body = """<main><div class=card><h1>Sign in another screen</h1>
<p>Type the code shown on the TV or tablet.</p>
<form method=get action=/pair><input name=c autocapitalize=characters autocomplete=off placeholder="ABC-DEF" required>
<div class=err>%s</div><button type=submit>Continue</button></form>
<a class="btn sec" href=/devices>My devices</a></div></main>""" % html.escape(msg)
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
<p style="margin-top:14px">Signed in as %s. <a href=/devices>My devices</a></p>
</div></main>""" % (html.escape(code_fmt(code)), html.escape(ua_label(pairing["ua"])), html.escape(pairing["ip"] or "?"),
                    "requested %ds ago" % max(0, now() - pairing["created"]),
                    html.escape(ua_label(pairing["ua"]), quote=True), html.escape(user))
    script = """
const CODE = %s;
async function answer(allow) {
  const g = document.querySelector('input[name=g]:checked').value;
  const r = await post('/_auth/pair/approve', { code: CODE, allow, grant: g, label: $id('label').value });
  if (r.error) { $id('err').textContent = r.error; return; }
  $id('allow').style.display = $id('deny').style.display = 'none';
  $id('ok').textContent = allow ? 'Done. The screen signs in within a few seconds.' : 'Denied.';
}
$id('allow').onclick = () => answer(true);
$id('deny').onclick = () => answer(false);
""" % json.dumps(code)
    return page("Allow this screen?", body, script)


def devices_page(u):
    admin = '<a class="btn sec" href=/users>People and invites</a>' if u.get("admin") else ""
    body = """<main><div class="card wide">
<h1>My devices</h1><p>Signed in as <b>%s</b>. Every app on every device is listed; revoke anything you don't recognise.</p>
<h2>Signed in</h2><div id=sessions class=mut>Loading…</div>
<button id=all class="sec">Sign out everywhere</button>
<h2>Passkeys</h2><div id=passkeys class=mut></div>
<button id=add class=sec style="display:none">Add a passkey on this device</button>
<div class=err id=err></div><div class=ok id=ok></div>
<h2>Sign in a TV or tablet</h2>
<p>Open the app on it, then scan its QR code with this phone, or type its code here:</p>
<form method=get action=/pair style="display:flex;gap:8px"><input name=c autocapitalize=characters autocomplete=off placeholder="ABC-DEF" required>
<button type=submit class=small>Go</button></form>
%s
<a class="btn sec" href=/>Home</a>
</div></main>""" % (html.escape(u.get("display") or u["name"]), admin)
    script = """
const KIND = { passkey: 'passkey', password: 'password', paired: 'paired by phone', sso: 'signed in via auth', invite: 'invite' };
async function load() {
  const r = await fetch('/_auth/devices').then(r => r.json());
  $id('sessions').innerHTML = r.sessions.map(s => `<div class=row><div class=t>${esc(s.label)}<span class=tag>${esc(s.app)}</span>${s.current ? ' <b>(this browser)</b>' : ''}
    <small>${esc(KIND[s.kind] || s.kind)} · last used ${ago(s.last_seen)} · ${esc(s.ip || '')} · until ${new Date(s.expires*1000).toLocaleDateString()}</small></div>
    ${s.current ? '' : `<button class="small danger" data-s="${s.id}">Revoke</button>`}</div>`).join('') || 'None';
  $id('passkeys').innerHTML = r.passkeys.map(p => `<div class=row><div class=t>${esc(p.label)}
    <small>added ${ago(p.created)} · used ${ago(p.last_used)}</small></div>
    <button class="small danger" data-p="${p.id}">Remove</button></div>`).join('') || 'No passkeys yet.';
  document.querySelectorAll('[data-s]').forEach(b => b.onclick = async () => { await post('/_auth/session/revoke', { id: b.dataset.s }); load(); });
  document.querySelectorAll('[data-p]').forEach(b => b.onclick = async () => {
    if (!confirm('Remove this passkey? That device will need another way to sign in.')) return;
    await post('/_auth/passkey/delete', { id: b.dataset.p }); load(); });
}
$id('all').onclick = async () => { if (!confirm('Sign out every app on every device (this one too)?')) return;
  await post('/_auth/session/revoke_all'); location.href = '/login'; };
if (hasPasskeys) { const a = $id('add'); a.style.display = '';
  a.onclick = () => createPasskey().then(() => { $id('ok').textContent = 'Passkey added.'; load(); }).catch(e => { $id('err').textContent = why(e); }); }
load();
"""
    return page("My devices · Nellika", body, script)


def enroll_page(token, user):
    if not user:
        return page("Passkey setup", "<main><div class=card><h1>Link expired</h1><p>Ask for a new setup link.</p></div></main>")
    body = """<main><div class=card><h1>Set up your passkey</h1>
<p>Account <b>%s</b>. Your phone stores the passkey (Face ID / fingerprint).</p>
<button id=go>Create passkey</button><div class=err id=err></div></div></main>""" % html.escape(user)
    script = """
$id('go').onclick = () => (hasPasskeys ? createPasskey({ enroll: %s }) : Promise.reject(new Error('This browser has no passkey support.')))
  .then(() => { location.href = '/devices'; }).catch(e => { $id('err').textContent = why(e); });
""" % json.dumps(token)
    return page("Passkey setup", body, script)


def invite_page(token, inv):
    if not inv:
        return page("Invite", "<main><div class=card><h1>Invite expired</h1><p>This invite was used already or has expired. Ask for a new one.</p></div></main>")
    body = """<main><div class=card><h1>Join Nellika</h1>
<p><b>%s</b> invited you%s. Pick a user name, then create a passkey: your phone keeps it (Face ID / fingerprint), so there is no password.</p>
<label class=mut for=name>Your name</label><input id=display maxlength=60 autocomplete=name placeholder="e.g. Emma">
<label class=mut for=user>User name (lowercase, no spaces)</label>
<input id=user maxlength=32 autocapitalize=none autocorrect=off spellcheck=false placeholder="e.g. emma">
<button id=go>Create my passkey</button><div class=err id=err></div></div></main>""" % (
        html.escape(inv.get("created_by") or "Someone"), (" (%s)" % html.escape(inv["note"])) if inv.get("note") else "")
    script = """
const T = %s;
$id('display').oninput = () => { if (!$id('user').dataset.touched) $id('user').value = $id('display').value.toLowerCase().replace(/[^a-z0-9._-]+/g, '').slice(0, 32); };
$id('user').oninput = () => { $id('user').dataset.touched = 1; };
$id('go').onclick = () => {
  if (!hasPasskeys) { $id('err').textContent = 'This browser has no passkey support: open the invite on your phone.'; return; }
  createPasskey({ invite: T, username: $id('user').value.trim(), display: $id('display').value.trim() })
    .then(() => { location.href = '/'; }).catch(e => { $id('err').textContent = why(e); });
};
""" % json.dumps(token)
    return page("Join Nellika", body, script)


def users_page(u):
    body = """<main><div class="card wide">
<h1>People</h1><p>Who can sign in. What each person may do is up to each app.</p>
<div id=users class=mut>Loading…</div>
<h2>Invite someone</h2>
<p>The link works once, for 7 days. Send it, or let them scan the QR code with their phone.</p>
<input id=note maxlength=60 placeholder="Note, e.g. Emma's phone (optional)">
<button id=mk>Create invite link</button>
<div id=inv style="display:none"><div class=qr id=invqr style="margin-top:12px"></div><p class=link id=invlink></p>
<button id=copy class=sec>Copy link</button></div>
<h2>Open invites</h2><div id=invites class=mut></div>
<div class=err id=err></div>
<a class="btn sec" href=/devices>My devices</a><a class="btn sec" href=/>Home</a>
</div></main>"""
    script = """
const ME = %s;
async function act(path, body) { const r = await post(path, body); if (r.error) $id('err').textContent = r.error; load(); }
async function load() {
  const r = await fetch('/_auth/users').then(r => r.json());
  if (r.error) { $id('users').textContent = r.error; return; }
  $id('users').innerHTML = r.users.map(p => `<div class=row><div class=t>${esc(p.display || p.name)} <span class=tag>${esc(p.name)}</span>${p.admin ? '<span class=tag>admin</span>' : ''}${p.disabled ? '<span class=tag>disabled</span>' : ''}
    <small>${p.passkeys} passkey(s) · ${p.devices} device(s) · last seen ${ago(p.last_seen)}${p.invited_by ? ' · invited by ' + esc(p.invited_by) : ''}</small></div>
    ${p.name === ME ? '<span class=mut>you</span>' : `<span>
      <button class=small data-a="${esc(p.name)}">${p.admin ? 'Remove admin' : 'Make admin'}</button>
      <button class=small data-d="${esc(p.name)}">${p.disabled ? 'Enable' : 'Disable'}</button>
      <button class="small danger" data-x="${esc(p.name)}">Delete</button></span>`}</div>`).join('');
  $id('invites').innerHTML = r.invites.map(i => `<div class=row><div class=t>${esc(i.note || 'invite')}<small>by ${esc(i.created_by)} · expires ${new Date(i.expires*1000).toLocaleDateString()}</small></div>
    <button class="small danger" data-i="${i.id}">Revoke</button></div>`).join('') || 'None';
  const byName = n => r.users.find(p => p.name === n);
  document.querySelectorAll('[data-a]').forEach(b => b.onclick = () => act('/_auth/user/update', { name: b.dataset.a, admin: !byName(b.dataset.a).admin }));
  document.querySelectorAll('[data-d]').forEach(b => b.onclick = () => act('/_auth/user/update', { name: b.dataset.d, disabled: !byName(b.dataset.d).disabled }));
  document.querySelectorAll('[data-x]').forEach(b => b.onclick = () => { if (confirm('Delete ' + b.dataset.x + ' with all passkeys and devices?')) act('/_auth/user/delete', { name: b.dataset.x }); });
  document.querySelectorAll('[data-i]').forEach(b => b.onclick = () => act('/_auth/invite/revoke', { id: b.dataset.i }));
}
$id('mk').onclick = async () => {
  const r = await post('/_auth/invite/create', { note: $id('note').value.trim() });
  if (r.error) { $id('err').textContent = r.error; return; }
  $id('inv').style.display = ''; $id('invqr').innerHTML = r.svg; $id('invlink').textContent = r.link;
  $id('copy').onclick = () => navigator.clipboard && navigator.clipboard.writeText(r.link).then(() => { $id('copy').textContent = 'Copied'; });
  load();
};
load();
""" % json.dumps(u["name"])
    return page("People · Nellika", body, script)


# ----------------------------------------------------------------------------- http
class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, code, body=b"", ctype="text/html; charset=utf-8", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if ctype.startswith("text/html"):
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "same-origin")
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _json(self, obj, code=200, extra=None):
        return self._send(code, json.dumps(obj).encode(), "application/json", extra)

    def _redirect(self, loc, extra=None):
        return self._send(302, b"", extra=[("Location", loc)] + (extra or []))

    def host(self):
        return (self.headers.get("Host") or "").split(":")[0].strip().lower()

    def ip(self):
        return self.headers.get("X-Real-IP") or self.client_address[0]

    def ua(self):
        return self.headers.get("User-Agent", "")

    def cookie(self, name):
        for part in self.headers.get("Cookie", "").split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                if k == name:
                    return v
        return None

    def session(self):
        """The signed-in session for THIS host (sessions are bound to the host that set them)."""
        host = self.host()
        v = self.cookie(COOKIE)
        if v and v.startswith("v2_"):
            s = self._session_row(sha(v[3:]), host)
            if s:
                return s
        if host == LEGACY_HOST:
            v = self.cookie(LEGACY_COOKIE)
            if v and v.startswith("v2_"):
                return self._session_row(sha(v[3:]), host)
            if v and check_legacy_token(v):
                u = active_user(OWNER)
                return {"user": OWNER, "sid": None, "kind": "legacy", "expires": now() + MAXAGE, "label": "",
                        "display": u.get("display") if u else OWNER, "admin": 1} if u else None
        return None

    def _session_row(self, sid, host):
        row = one("SELECT s.*, u.display, u.admin, u.disabled FROM sessions s JOIN users u ON u.name = s.user "
                  "WHERE s.id=? AND s.app=? AND s.expires>?", (sid, host, now()))
        if not row or row.get("disabled"):
            return None
        if now() - (row["last_seen"] or 0) > 60:
            q("UPDATE sessions SET last_seen=?, ip=? WHERE id=?", (now(), self.ip(), sid))
        return {"user": row["user"], "sid": sid, "kind": row["kind"], "expires": row["expires"],
                "label": row["label"], "display": row.get("display") or row["user"], "admin": row.get("admin") or 0}

    def body_json(self):
        if not self.headers.get("Content-Type", "").startswith("application/json"):
            raise PermissionError("bad content type")
        origin = self.headers.get("Origin")
        if origin and origin != AUTH_ORIGIN:   # CSRF: same-origin fetches from the auth pages only
            raise PermissionError("bad origin")
        n = int(self.headers.get("Content-Length") or 0)
        if n > 64 * 1024:
            raise ValueError("request too large")
        return json.loads(self.rfile.read(n).decode() or "{}") if n else {}

    def central_cookie(self, user, kind, label=None, ttl=MAXAGE):
        value, maxage = new_session(user, kind, label, self.ua(), self.ip(), AUTH_HOST, ttl)
        return ("Set-Cookie", cookie_header(COOKIE, value, maxage))

    # ------------------------------------------------------------------ GET
    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        path, qs = u.path, urllib.parse.parse_qs(u.query)
        arg = lambda k: (qs.get(k) or [""])[0]
        if self.host() == AUTH_HOST:
            return self.auth_get(path, arg)
        return self.app_get(path, arg)

    # app hosts: the few endpoints an app needs
    def app_get(self, path, arg):
        host = self.host()
        if path == "/_authcheck":
            s = self.session()
            if not s:
                return self._send(401, b"")
            return self._send(200, b"", extra=[("X-Auth-User", s["user"]),
                                               ("X-Auth-Name", urllib.parse.quote(s["display"] or s["user"])),
                                               ("X-Auth-Admin", "1" if s["admin"] else "0")])
        if path == "/_auth/me":
            s = self.session()
            return self._json({"user": s["user"], "name": s["display"], "admin": bool(s["admin"]),
                               "account": AUTH_ORIGIN + "/devices"} if s else {"user": None}, 200 if s else 401)
        if path == "/_auth/start":
            # nginx sends a signed-out visitor here (error_page 401); X-Original-URI = what they asked for
            if not app_host_ok(host):
                return self._send(403, b"this host is not set up for Nellika sign-in")
            rd = "https://%s%s" % (host, local_path(self.headers.get("X-Original-URI") or arg("rd")))
            return self._redirect(AUTH_ORIGIN + "/authorize?rd=" + urllib.parse.quote(rd, safe=""))
        if path == "/_auth/callback":
            code = one("SELECT * FROM codes WHERE code=? AND app=? AND expires>?", (sha(arg("code")), host, now()))
            if not code or not active_user(code["user"]):
                return self._redirect(AUTH_ORIGIN + "/authorize?rd=" + urllib.parse.quote("https://%s/" % host, safe=""))
            q("DELETE FROM codes WHERE code=?", (code["code"],))   # single use
            ttl = max(60, min(MAXAGE, (code["session_expires"] or now() + MAXAGE) - now()))
            value, maxage = new_session(code["user"], "sso", code["label"], self.ua(), self.ip(), host, ttl)
            return self._redirect(local_path(code["rd"]), [("Set-Cookie", cookie_header(COOKIE, value, maxage))])
        if path in ("/_auth/logout", "/_logout"):
            s = self.session()
            if s and s["sid"]:
                q("DELETE FROM sessions WHERE id=?", (s["sid"],))
            extra = [("Set-Cookie", cookie_header(COOKIE, "", 0))]
            if host == LEGACY_HOST:
                extra.append(("Set-Cookie", cookie_header(LEGACY_COOKIE, "", 0)))
            return self._redirect(AUTH_ORIGIN + "/", extra)
        # the stream-only service had its pages on the app host: send them to the auth host
        legacy = {"/_login": "/login", "/_devices": "/devices", "/_pair": "/pair", "/_enroll": "/enroll"}
        if path in legacy:
            query = urllib.parse.urlparse(self.path).query
            if path == "/_login":
                rd = "https://%s%s" % (host, local_path(arg("next")))
                return self._redirect(AUTH_ORIGIN + "/authorize?rd=" + urllib.parse.quote(rd, safe=""))
            return self._redirect(AUTH_ORIGIN + legacy[path] + ("?" + query if query else ""))
        return self._send(404, b"not found")

    # auth host: pages + JSON reads
    def auth_get(self, path, arg):
        if path == "/authorize":
            rd = arg("rd")
            p = urllib.parse.urlparse(rd)
            if p.scheme != "https" or not app_host_ok(p.hostname) or p.port or p.username or p.password:
                return self._send(400, page("Sign in", "<main><div class=card><h1>Unknown app</h1><p>That address is not a Nellika app.</p></div></main>"))
            s = self.session()
            if not s:
                return self._redirect("/login?next=" + urllib.parse.quote("/authorize?rd=" + urllib.parse.quote(rd, safe=""), safe=""))
            code = secrets.token_urlsafe(32)
            q("INSERT INTO codes (code,user,app,rd,expires,session_expires,label) VALUES (?,?,?,?,?,?,?)",
              (sha(code), s["user"], p.hostname, (p.path or "/") + ("?" + p.query if p.query else ""),
               now() + CODE_TTL, s["expires"], s.get("label")))
            return self._redirect("https://%s/_auth/callback?code=%s" % (p.hostname, code))
        if path == "/login":
            return self._send(200, login_page(local_path(arg("next"))))
        if path == "/logout":
            s = self.session()
            if s and s["sid"]:
                q("DELETE FROM sessions WHERE id=?", (s["sid"],))
            return self._redirect("/login", [("Set-Cookie", cookie_header(COOKIE, "", 0))])
        if path == "/enroll":
            row = one("SELECT user FROM enroll WHERE token=? AND expires>?", (sha(arg("t")), now()))
            return self._send(200, enroll_page(arg("t"), row["user"] if row else None))
        if path == "/invite":
            inv = one("SELECT * FROM invites WHERE token=? AND expires>? AND used_by IS NULL", (sha(arg("t")), now()))
            return self._send(200, invite_page(arg("t"), inv))
        s = self.session()
        if not s:
            if path.startswith("/_auth/"):
                return self._json({"error": "sign in first"}, 401)
            return self._redirect("/login?next=" + urllib.parse.quote(self.path, safe=""))
        me = active_user(s["user"])
        if path == "/":
            return self._send(200, home_page(me))
        if path == "/pair":
            code = norm_code(arg("c"))
            pairing = one("SELECT * FROM pairings WHERE code=? AND state='pending' AND expires>?", (code, now())) if code else None
            return self._send(200, pair_page(code, pairing, s["user"]))
        if path == "/devices":
            return self._send(200, devices_page(me))
        if path == "/users":
            if not me.get("admin"):
                return self._send(403, page("People", "<main><div class=card><h1>Admins only</h1></div></main>"))
            return self._send(200, users_page(me))
        if path == "/_auth/devices":
            sessions = q("SELECT id,kind,label,ip,created,expires,last_seen,app FROM sessions WHERE user=? AND expires>? "
                         "ORDER BY last_seen DESC", (s["user"], now()))
            for x in sessions:
                x["current"] = x["id"] == s["sid"]
            passkeys = q("SELECT id,label,created,last_used FROM passkeys WHERE user=? ORDER BY created", (s["user"],))
            return self._json({"user": s["user"], "sessions": sessions, "passkeys": passkeys})
        if path == "/_auth/users":
            if not me.get("admin"):
                return self._json({"error": "admins only"}, 403)
            t = now()
            users = q("""SELECT u.name, u.display, u.admin, u.disabled, u.created, u.invited_by,
                           (SELECT count(*) FROM passkeys p WHERE p.user=u.name) AS passkeys,
                           (SELECT count(*) FROM sessions s WHERE s.user=u.name AND s.expires>?) AS devices,
                           (SELECT max(last_seen) FROM sessions s WHERE s.user=u.name) AS last_seen
                         FROM users u ORDER BY u.admin DESC, u.name""", (t,))
            invites = q("SELECT substr(token,1,16) AS id, created_by, note, created, expires FROM invites "
                        "WHERE used_by IS NULL AND expires>? ORDER BY created DESC", (t,))
            return self._json({"users": users, "invites": invites})
        return self._send(404, b"not found")

    # ------------------------------------------------------------------ POST (auth host only)
    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if self.host() != AUTH_HOST:
            return self._json({"error": "not found"}, 404)
        try:
            if path == "/login":
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

    def require(self, admin=False):
        s = self.session()
        if not s:
            raise PermissionError("sign in first")
        if admin and not s["admin"]:
            raise PermissionError("admins only")
        return s

    def password_login(self):
        n = int(self.headers.get("Content-Length") or 0)
        data = urllib.parse.parse_qs(self.rfile.read(min(n, 8192)).decode("utf-8", "replace"))
        user = (data.get("username") or [""])[0].strip().lower()
        pw = (data.get("password") or [""])[0]
        nxt = local_path((data.get("next") or ["/"])[0])
        if too_many_fails(self.ip()):
            return self._send(429, login_page(nxt, "Too many attempts, try again in 15 minutes."))
        if valid_login(user, pw) and active_user(user):
            return self._redirect(nxt, [self.central_cookie(user, "password")])
        FAILS.setdefault(self.ip(), []).append(time.time())
        return self._send(401, login_page(nxt, "Wrong username or password."))

    # passkeys -----------------------------------------------------------------
    def api_register_begin(self, body):
        if body.get("invite"):
            inv = one("SELECT * FROM invites WHERE token=? AND expires>? AND used_by IS NULL", (sha(body["invite"]), now()))
            if not inv:
                raise PermissionError("this invite was used already or has expired")
            name = str(body.get("username") or "").strip().lower()
            if not USERNAME_RE.match(name):
                raise ValueError("user name: 2-32 characters, lowercase letters, digits, . _ -")
            if user_row(name):
                raise ValueError("that user name is taken, pick another")
            display = str(body.get("display") or "").strip()[:60] or name
            handle = bytes_to_base64url(secrets.token_bytes(32))
            opts = register_options(name, handle, display)
            cid = put_challenge("register", opts.challenge, user=name, handle=handle, display=display, invite=body["invite"])
        elif body.get("enroll"):
            row = one("SELECT user FROM enroll WHERE token=? AND expires>?", (sha(body["enroll"]), now()))
            if not row or not active_user(row["user"]):
                raise PermissionError("setup link expired")
            u = ensure_user(row["user"])
            opts = register_options(u["name"], u["handle"], u.get("display"))
            cid = put_challenge("register", opts.challenge, user=u["name"], enroll=body["enroll"])
        else:
            s = self.require()
            u = user_row(s["user"])
            opts = register_options(u["name"], u["handle"], u.get("display"))
            cid = put_challenge("register", opts.challenge, user=u["name"])
        return self._json({"cid": cid, "options": json.loads(options_to_json(opts))})

    def api_register_finish(self, body):
        c = take_challenge(body.get("cid"), "register")
        if c.get("invite"):
            if not one("SELECT 1 AS x FROM invites WHERE token=? AND expires>? AND used_by IS NULL", (sha(c["invite"]), now())):
                raise PermissionError("this invite was used already or has expired")
        elif c.get("enroll"):
            if not one("SELECT 1 AS x FROM enroll WHERE token=? AND expires>?", (sha(c["enroll"]), now())):
                raise PermissionError("setup link expired")
        else:
            s = self.session()
            if not s or s["user"] != c["user"]:
                raise PermissionError("sign in first")
        v = verify_registration_response(credential=body["credential"], expected_challenge=c["challenge"],
                                         expected_rp_id=RP_ID, expected_origin=AUTH_ORIGIN, require_user_verification=False)
        label = ua_label(self.ua())
        if c.get("invite"):
            with _db_lock:
                inv = one("SELECT * FROM invites WHERE token=? AND used_by IS NULL", (sha(c["invite"]),))
                if not inv or user_row(c["user"]):
                    raise PermissionError("this invite was used already, or the user name was just taken")
                q("INSERT INTO users (name, handle, display, admin, disabled, created, invited_by) VALUES (?,?,?,0,0,?,?)",
                  (c["user"], c["handle"], c["display"], now(), inv["created_by"]))
                q("UPDATE invites SET used_by=?, used_at=? WHERE token=?", (c["user"], now(), inv["token"]))
        q("INSERT INTO passkeys (id,user,pubkey,sign_count,label,created,last_used) VALUES (?,?,?,?,?,?,NULL)",
          (bytes_to_base64url(v.credential_id), c["user"], v.credential_public_key, v.sign_count, label, now()))
        extra = []
        if c.get("enroll"):
            q("DELETE FROM enroll WHERE token=?", (sha(c["enroll"]),))
        if c.get("enroll") or c.get("invite"):
            extra = [self.central_cookie(c["user"], "passkey")]
        return self._json({"ok": True}, extra=extra)

    def api_login_begin(self, body):
        opts = generate_authentication_options(rp_id=RP_ID, user_verification=UserVerificationRequirement.PREFERRED)
        return self._json({"cid": put_challenge("login", opts.challenge), "options": json.loads(options_to_json(opts))})

    def api_login_finish(self, body):
        c = take_challenge(body.get("cid"), "login")
        cred = body["credential"]
        row = one("SELECT * FROM passkeys WHERE id=?", (credential_id(cred),))
        if not row:
            raise PermissionError("unknown passkey (removed?)")
        u = active_user(row["user"])
        if not u:
            raise PermissionError("this account is disabled")
        handle = (cred.get("response") or {}).get("userHandle")
        if handle and handle != u["handle"]:
            raise PermissionError("passkey does not match its account")
        v = verify_authentication_response(credential=cred, expected_challenge=c["challenge"], expected_rp_id=RP_ID,
                                           expected_origin=AUTH_ORIGIN, credential_public_key=row["pubkey"],
                                           credential_current_sign_count=row["sign_count"], require_user_verification=False)
        q("UPDATE passkeys SET sign_count=?, last_used=? WHERE id=?", (v.new_sign_count, now(), row["id"]))
        return self._json({"ok": True, "next": local_path(body.get("next"))},
                          extra=[self.central_cookie(row["user"], "passkey")])

    def api_passkey_delete(self, body):
        s = self.require()
        q("DELETE FROM passkeys WHERE id=? AND user=?", (str(body.get("id")), s["user"]))
        return self._json({"ok": True})

    # phone pairing ---------------------------------------------------------------
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
        url = "%s/pair?c=%s" % (AUTH_ORIGIN, code)
        return self._json({"code": code_fmt(code), "poll": poll, "url": url, "svg": qr_svg(url), "expires_in": PAIR_TTL})

    def api_pair_poll(self, body):
        row = one("SELECT * FROM pairings WHERE poll=?", (sha(str(body.get("poll"))),))
        if not row or (row["state"] == "pending" and row["expires"] < now()):
            return self._json({"state": "expired"})
        if row["state"] == "approved":
            q("UPDATE pairings SET state='used' WHERE code=? AND state='approved'", (row["code"],))
            if not active_user(row["user"]):
                return self._json({"state": "denied"})
            return self._json({"state": "approved"}, extra=[self.central_cookie(row["user"], "paired", row["label"], row["grant_s"])])
        return self._json({"state": row["state"]})

    def api_pair_approve(self, body):
        s = self.require()
        code = norm_code(body.get("code"))
        row = one("SELECT * FROM pairings WHERE code=? AND state='pending' AND expires>?", (code, now()))
        if not row:
            raise ValueError("that code has expired, ask the screen for a new one")
        if body.get("allow"):
            grant = GRANTS.get(body.get("grant"), GRANTS["day"])
            label = (str(body.get("label") or "") or ua_label(row["ua"]))[:60]
            q("UPDATE pairings SET state='approved', user=?, label=?, grant_s=? WHERE code=?", (s["user"], label, grant, code))
        else:
            q("UPDATE pairings SET state='denied' WHERE code=?", (code,))
        return self._json({"ok": True})

    # sessions ---------------------------------------------------------------------
    def api_session_revoke(self, body):
        s = self.require()
        q("DELETE FROM sessions WHERE id=? AND user=?", (str(body.get("id")), s["user"]))
        return self._json({"ok": True})

    def api_session_revoke_all(self, body):
        s = self.require()
        q("DELETE FROM sessions WHERE user=?", (s["user"],))
        return self._json({"ok": True}, extra=[("Set-Cookie", cookie_header(COOKIE, "", 0))])

    # people (admins) -------------------------------------------------------------
    def api_invite_create(self, body):
        s = self.require(admin=True)
        token = secrets.token_urlsafe(24)
        q("INSERT INTO invites (token, created_by, note, created, expires) VALUES (?,?,?,?,?)",
          (sha(token), s["user"], str(body.get("note") or "")[:60], now(), now() + INVITE_TTL))
        link = "%s/invite?t=%s" % (AUTH_ORIGIN, token)
        return self._json({"link": link, "svg": qr_svg(link), "expires_in": INVITE_TTL})

    def api_invite_revoke(self, body):
        self.require(admin=True)
        ident = str(body.get("id") or "")
        if len(ident) < 16:
            raise ValueError("unknown invite")
        q("DELETE FROM invites WHERE substr(token,1,16)=? AND used_by IS NULL", (ident[:16],))
        return self._json({"ok": True})

    def api_user_update(self, body):
        s = self.require(admin=True)
        name = str(body.get("name") or "")
        if not user_row(name):
            raise ValueError("unknown user")
        if name == s["user"] or name == OWNER:
            raise PermissionError("you cannot change your own (or the owner's) admin / disabled state")
        if "admin" in body:
            q("UPDATE users SET admin=? WHERE name=?", (1 if body["admin"] else 0, name))
        if "disabled" in body:
            q("UPDATE users SET disabled=? WHERE name=?", (1 if body["disabled"] else 0, name))
            if body["disabled"]:
                q("DELETE FROM sessions WHERE user=?", (name,))
        return self._json({"ok": True})

    def api_user_delete(self, body):
        s = self.require(admin=True)
        name = str(body.get("name") or "")
        if name == s["user"] or name == OWNER:
            raise PermissionError("you cannot delete yourself or the owner")
        for sql in ("DELETE FROM sessions WHERE user=?", "DELETE FROM passkeys WHERE user=?",
                    "DELETE FROM codes WHERE user=?", "DELETE FROM enroll WHERE user=?", "DELETE FROM users WHERE name=?"):
            q(sql, (name,))
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
        "/_auth/session/revoke_all": api_session_revoke_all,
        "/_auth/invite/create": api_invite_create,
        "/_auth/invite/revoke": api_invite_revoke,
        "/_auth/user/update": api_user_update,
        "/_auth/user/delete": api_user_delete,
    }


# ----------------------------------------------------------------------------- CLI
def set_password(user):
    pw = "-".join(secrets.token_hex(2) for _ in range(4))
    args = ["htpasswd", "-iB"] + ([] if os.path.exists(HTPASSWD) else ["-c"]) + [HTPASSWD, user]
    subprocess.run(args, input=pw, text=True, capture_output=True, timeout=10, check=True)
    os.chmod(HTPASSWD, 0o640)
    return pw


def enroll_link(user, hours=24):
    token = secrets.token_urlsafe(24)
    q("INSERT INTO enroll (token, user, expires) VALUES (?,?,?)", (sha(token), user, now() + hours * 3600))
    return "%s/enroll?t=%s" % (AUTH_ORIGIN, token)


def invite_link(note="", created_by=None):
    token = secrets.token_urlsafe(24)
    q("INSERT INTO invites (token, created_by, note, created, expires) VALUES (?,?,?,?,?)",
      (sha(token), created_by or OWNER, note[:60], now(), now() + INVITE_TTL))
    return "%s/invite?t=%s" % (AUTH_ORIGIN, token)


def janitor():
    while True:
        try:
            purge()
        except Exception as e:
            print("purge failed: %r" % e, file=sys.stderr, flush=True)
        time.sleep(600)


if __name__ == "__main__":
    db_init()
    cmd = sys.argv[1:] or ["serve"]
    if cmd[0] == "enroll" and len(cmd) == 2:
        print(enroll_link(cmd[1]))
    elif cmd[0] == "passwd" and len(cmd) == 2:
        print(set_password(cmd[1]))
    elif cmd[0] == "invite":
        print(invite_link(" ".join(cmd[1:])))
    elif cmd[0] == "adduser" and len(cmd) in (2, 3):
        ensure_user(cmd[1], admin=len(cmd) == 3 and cmd[2] == "admin")
        print(enroll_link(cmd[1]))
    elif cmd[0] == "serve":
        threading.Thread(target=janitor, daemon=True).start()
        ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
    else:
        sys.exit("usage: nellika-auth.py [serve] | enroll <user> | passwd <user> | invite [note] | adduser <name> [admin]")
