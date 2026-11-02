# Nellika sign-in (auth.nellika.io)

One sign-in for every Nellika web app that is reverse-proxied through **nell_remote** (the nginx VPS),
whichever server the app itself runs on. The sign-in says **who** someone is; each app decides **what**
they may do.

## People
- **Passkeys** (Face ID / fingerprint, rp id `nellika.io`), a **TV / tablet** approved from a signed-in
  phone (QR + short code; today / 1 week / long-term), and a password fallback for the owner.
- **Invite-only accounts**: an admin opens <https://auth.nellika.io/users>, makes an invite link / QR
  (single use, 7 days); the person picks a user name and creates a passkey with it.
- <https://auth.nellika.io/devices>: every signed-in app on every device, revoke any of them, sign out
  everywhere, add a passkey, approve a TV by its code.
- Disabling or deleting a person ends all their sessions on the next request.

## Protecting an app (2 includes)
```nginx
server {
    server_name myapp.nellika.io;            # any *.nellika.io host on nell_remote
    ...
    include snippets/nellika-auth-server.conf;

    location / {
        include snippets/nellika-auth-location.conf;
        proxy_pass http://my-backend;
    }
}
```
Signed-out visitors are sent to auth.nellika.io and come straight back; the app gets **its own**
host-only cookie (no cookie is shared between hosts). Already signed in elsewhere = no second prompt.

## What the app receives
Trusted request headers (nginx overwrites anything the client sent):

| header | value |
|---|---|
| `X-Auth-User` | account name: lowercase `[a-z0-9._-]` |
| `X-Auth-Name` | display name, URL-encoded UTF-8 |
| `X-Auth-Admin` | `1` = Nellika admin (manages people), else `0` |

Authorization is the app's job: map `X-Auth-User` to the app's own roles / limits. From the browser an
app page can also call `GET /_auth/me` (JSON: user, name, admin, account link) and link to
`/_auth/logout` (signs out of this app only) or <https://auth.nellika.io/devices>.

## Operating
- Service `nellika-auth` (127.0.0.1:8091, `/opt/nellika-auth`, venv python3.11 + webauthn + segno),
  database `/var/lib/nellika-auth/auth.db`. Deploy: `vps/deploy-nellika-auth.sh` (backup, rollback).
- CLI on the VPS (`/opt/nellika-auth/venv/bin/python /opt/nellika-auth/nellika-auth.py ...`):
  `invite [note]` (invite link), `enroll <user>` (passkey setup link for an existing account),
  `adduser <name> [admin]`, `passwd <user>` (password fallback).
