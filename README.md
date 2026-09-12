# kodi-stream

On-demand HLS streaming of a [Kodi](https://kodi.tv) library to phones and laptops, running on the
Kodi box itself (NanoPC-T6 / RK3588). Browse the library (movies + TV), press play, and watch a 720p
H.264 + AAC HLS stream with subtitle and audio-track selection, resume shared with Kodi, behind an
iOS-Keychain-friendly cookie login. Companion to [torrent-adder](https://github.com/dgoo2308/torrent-adder).

## What it does
- **Catalogue** from Kodi's `MyVideos*.db` (read-only): movies, shows, seasons, episodes, posters, search.
- **Playback** decided per item: direct play, remux, or transcode to 720p on the fly, real-time paced,
  as a rolling HLS window on the NVMe (nothing persisted).
- **Player** (single page, `static/index.html` + vendored hls.js): full-movie seek, ±skip, audio &
  subtitle pickers, fullscreen, auto-hiding controls; seeking/track-change restart the transcode at the point.
- **Resume + watched** shared with Kodi (JSON-RPC when Kodi runs, the library DB `bookmark`/`files`
  rows when it does not), both directions.
- **Access**: reverse-proxied via frp to a VPS; a cookie login form (Keychain-friendly) with HTTP
  Basic auth as fallback (`vps/`).

## Encoder note (important)
Video is encoded with **software x264** by default. The RK3588 VEPU580 hardware encoder was
investigated at length: it corrupts the top macroblock rows under DDR/memory-bus contention (its
reference reads get starved), which is unavoidable while decode/serve run alongside. x264 at 720p is
~1 CPU core and clean everywhere. The hardware path (chunked decode→RAM→encode) is kept in the code
behind `allow_hw_encoder` for the day the contention or the 10-bit NV15 re-encode path is solved.
Full investigation and decisions: [`docs/kodi-stream.md`](docs/kodi-stream.md).

## Layout
- `stream-api.py` — the service (stdlib `ThreadingHTTPServer`): catalogue, session manager, resume sync.
- `static/` — the player page + vendored `hls.min.js`.
- `nginx-kodi-stream.conf` — box nginx site (static + `/hls/` + `/api/` proxy + internal `/media/`).
- `kodi-stream.service` — systemd unit (user `pi`, memory/CPU caps).
- `vps/` — VPS side: `stream-auth.py` (cookie login), its unit, and the `stream.nellika.io` nginx vhost.

## Deploy (summary)
Box: copy `stream-api.py` + `static/` to `/opt/kodi-stream/`, install the nginx site and systemd unit,
`systemctl enable --now kodi-stream`. VPS: `vps/stream-auth.py` to `/opt/stream-auth/`, its unit,
generate `/etc/stream-auth.key`, install the nginx vhost. See `docs/kodi-stream.md` for the full runbook.
