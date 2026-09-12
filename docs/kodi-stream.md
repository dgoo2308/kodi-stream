# kodi-stream — runbook (MVP deployed 2026-09-12)

On-demand HLS streaming of the Kodi library for phones/laptops. Plan + design:
`docs/plan-hls-streaming-service-2026-09-12.md`. Source of truth in this repo: `services/kodi-stream/`.

## Auth — cookie login (2026-09-12, iOS home-screen friendly)
`stream.nellika.io` used HTTP Basic auth, which iOS home-screen (standalone) web apps cannot autofill
from Keychain. Added a **cookie login** on the VPS: an HTML form with `autocomplete=username`/
`current-password` → iOS offers to save & autofill it, validates against the shared `torrent-add.htpasswd`
(via `htpasswd -vi`), sets a signed (HMAC) 90-day cookie. nginx `satisfy any` accepts the cookie
(`auth_request` → `/_authcheck`) OR Basic auth (fallback for existing/programmatic clients); no auth →
`error_page 401` redirects to `/_login`. Files (repo `services/kodi-stream/vps/`): `stream-auth.py`
(stdlib service, `127.0.0.1:8091`, systemd `stream-auth.service`), `stream.nellika.io.conf`, key at
`/etc/stream-auth.key`. Only the stream vhost changed; `torrent-add.nellika.io` is a separate vhost,
untouched. Logout: `/_logout`.

## Where
- URL: **https://stream.nellika.io** (VPS nginx: wildcard cert + Basic auth "Torrent Services", same
  credentials as torrent-add) → frps → frpc `[kodi-stream]` → box nginx `127.0.0.1:8088`.
- Box: `/opt/kodi-stream/stream-api.py` (systemd `kodi-stream.service`, user pi, groups video/render/
  media, `MemoryMax=1200M Nice=10 CPUWeight=50`), API on `127.0.0.1:8090`; nginx site
  `/etc/nginx/sites-available/kodi-stream` (page + `/hls/` + `/api/` proxy + internal `/media/`
  alias of `/var/media/lacie/Media` for direct play); run dir `/home/pi/kodi-stream-run/<session>/`
  (rolling window, wiped on stop/start); page `/opt/kodi-stream/static/` (index.html + hls.js 1.5.17).
- Config overrides: `/opt/kodi-stream/config.json` (see `CONFIG` in the script: bitrates,
  `max_width`, `direct_max_bitrate`, `pace_realtime`, Kodi RPC creds, ffmpeg paths).

## How it plays (decision per item, `decide()` in the script)
| source | mode | who does the work |
|---|---|---|
| H.264 ≤1280w ≤3.5 Mbps 8-bit + AAC in MP4/MOV, no subtitle chosen | `direct` | nginx serves the file (range requests) |
| same class but MKV / non-AAC audio / subtitle chosen | `remux` | ffmpeg-rkmpp `-c:v copy`, audio→AAC, HLS |
| 8-bit H.264/HEVC/VP9/VP8/MPEG-2/AV1 | `transcode-hw` | mainline ffmpeg v4l2request decode → NV12 pipe → `h264_rkmpp` 720p 2.5 Mbps |
| 10-bit / XviD / anything else | `transcode-sw` | mainline ffmpeg SW decode (8 thr) → same pipe (refused if MemAvailable < 800 MB) |
Sessions are paced at real time (`-re`), 4 s segments, 8-segment window, ~15 MB on disk. Seek =
new session at the offset (page keeps absolute time). Text subtitles (embedded or `.srt` beside the
file) → WebVTT rendition in the HLS master (hls.js/Safari render; default track on). Resume: page
posts every 30 s / on pause / stop / page hide → Kodi JSON-RPC `SetMovieDetails`/`SetEpisodeDetails`
(playcount +1 at ≥90 %), or the `bookmark` table if Kodi is down.

## Verified 2026-09-12 (through box nginx)
catalogue (movies/search/shows/episodes), item probe, `transcode-hw` (3086 @600 s, ready in ~4 s,
+8 s produced in 8 s), `remux` (2270), `transcode-sw` 10-bit (3088), subtitles (2464 eng → master
`EXT-X-MEDIA:TYPE=SUBTITLES` + `stream_0_vtt.m3u8` + `.vtt`), `direct` (3020: 206 partial,
video/mp4), stop wipes run dir, resume round-trip via Kodi, 0 kernel encoder events.

## Operate
```
ssh kodi_root systemctl status kodi-stream nginx     # health
curl -s http://127.0.0.1:8088/api/health             # on the box
journalctl -u kodi-stream -f                         # API log (one line per request)
cat /home/pi/kodi-stream-run/*/ffmpeg.log            # live session: DEC/ENC command lines + errors
systemctl restart kodi-stream                        # kills the session too
```
Redeploy after editing the repo copy: `scp services/kodi-stream/* kodi:/home/pi/scratch/kodi-stream-deploy/`
then as root copy into `/opt/kodi-stream` / `/etc/nginx/sites-available/kodi-stream` /
`/etc/systemd/system/kodi-stream.service`, `nginx -t && systemctl reload nginx`,
`systemctl restart kodi-stream`.

## 2026-09-12 evening — "artifacts on moving objects" (Danny's phone) → ROOT CAUSE + FIX
Symptom: horizontal smears following motion, on several movies. Method: PSNR of encodes against the
identical raw frames (`ffmpeg … -lavfi psnr`, per-frame stats), contact sheets, and isolating each
stage. Findings (John Wick 2, 30 s, 720p, 2.5 Mbps):
| stage | result |
|---|---|
| `h264_rkmpp` fed from a raw FILE | min 39 dB, median 55, 0 bad frames — encoder + driver are fine |
| raw → pipe → encoder, unpaced | clean (0 bad) |
| raw → pipe → encoder, `-re` paced | 3 bad frames of 679 (encoder dislikes slow feed, minor) |
| HW decode (v4l2request) → file, unpaced | **bit-exact** with SW decode |
| HW decode → file, `-re` paced | bursts of torn frames (487-493, 602-6xx) — **the culprit** |
| HW decode `-re` + `-extra_hw_frames 12` → file | **bit-exact** |
| full paced pipeline + extra_hw_frames 12 | 4 low frames / 720 (cut + hard stretch, same in unpaced) |
| full pipeline unpaced + extra_hw_frames 12 | 0 bad, median 50 dB |
Root cause: when the HW decoder is throttled (pacing or pipe back-pressure) its V4L2 capture pool
runs dry and buffers still being read by `hwdownload` are recycled → torn frames → encoded faithfully
→ smears on motion. Fix deployed: decoder always runs with `-extra_hw_frames 12` (config
`extra_hw_frames`). Also added `pace_realtime=false` mode (no `-re`, keep all segments of the session,
`hls_list_size 0`) for max quality at the cost of a burst of CPU/disk per session (~1.1 GB/h, wiped on
stop). Burst pacing via SIGSTOP is NOT viable (the encoder's async frame/packet matching breaks).
Same lesson as Kodi's DRMPRIME `extra_hw_frames` (V4L2 `VIDEO_MAX_FRAME` = 32 caps DPB+extra).

## 2026-09-12 — HW-encoder smear: full investigation, root cause, and DECISION (SW encode)
Danny's remote playback smeared on the top ~1/8 of the frame on moving scenes, on every player.
After a long, at times misled, investigation the cause is now understood and the shipping decision made.

### ROOT CAUSE — DDR / memory-bus contention starves the VEPU580 encoder
The `h264_rkmpp` (VEPU580) encoder loses memory-bus arbitration whenever anything else touches DDR,
and reads stale reference data, smearing the top macroblock rows of inter frames. Proven by encoding
the SAME clean raw under different concurrent load (streaky frames / 866):

| concurrent activity while encoding a clean file | streaks |
|---|---|
| nothing (idle box) | **0** |
| the stream's own decoder running (decode+encode concurrent) | 10–17 |
| Kodi decoding 4K | 152 |
| Kodi + 2 extra decoders | 281 |

The decoder (rkvdec) is tolerant — it stalls and waits for the bus, so Kodi playback and the decoded
frames themselves are always clean (verified 0). Only the encoder, whose real-time reconstruction
cannot stall, corrupts. This is why it is confined to the top rows (its reference reads).

### What did NOT fix it (with evidence, so we don't repeat)
- **MPP single task slot (`task_cnt=1`, mpp.c patch): HARMFUL, reverted.** It made even an idle file
  encode 158 streaks (was 0). An earlier "48→6 fix" claim was a measurement confounded by Kodi state.
  The original dual-core MPP encodes a file cleanly (0); it is restored and is the correct MPP.
- **QoS priority (driver patch):** `QOS_PRIORITY` @ `0xfdf60000` (offset 0x08) default reads
  `0x80000000` (FlexNoC high-bit format, NOT the 2-bit field first assumed). `0x3` made it WORSE
  (489), `0xffffffff` best under heavy load (91) but **no help at light contention** (realistic
  6 stayed 6). Left as a live-tunable module param `rkvenc.qos_priority` (default 0 = no write).
- CACHABLE input buffers, larger pinned hwframe pool, every rate-control mode, `-flags +low_delay`,
  pacing (`-re`), bigger input `-thread_queue_size` / RAM ring buffer — none eliminated it.
- ⚠️ The kernel device-tree row-cache buffer is NOT the cause; a p4/DTB reflash would do nothing
  (the encoder external line buffer is only used above 4096 px wide; inactive at 720p).

### What helped most — chunked sequential decode→RAM→encode (Danny's idea)
Per HLS segment: HW-decode ~4s into `/dev/shm` (decoder only) → HW-encode that RAM buffer (encoder
only) → mux audio (CPU only). Decode and encode never overlap, so the encoder is not starved.
**Standalone: 0 streaks at 6.7x real time, zero SSD writes (RAM).** Implemented in `stream-api.py`
(`_launch_chunked`, `SessionManager._run_step`) and it is kept, dormant, behind `allow_hw_encoder`.
BUT in real playback nginx serves segments to the client concurrently with the encode, and that light
I/O is enough to bring a few smeared frames back — still visible on the iPhone. So it is close but
not clean enough to ship as the default.
- Bug fixed along the way: the chunked mux had no audio duration bound, so each 4s segment muxed the
  whole film's audio (a 114 MB "segment", "up and not playing"). Fixed with `-t seglen -shortest`.

### DECISION (2026-09-12): ship SOFTWARE encode (x264)
`default_encoder=x264`, `allow_hw_encoder=False`. `libx264 -preset veryfast` 720p is clean on every
player, ~1 CPU core at real time, HW decode still used for 8-bit sources. For 10-bit sources decode is
software anyway (see below), so a software 720p encode on top is cheap and the pragmatic choice.
The chunked HW path stays in the code for when the encoder-contention or the 10-bit path is solved.

### 10-bit and the NV15 path — THE NEXT THING TO WORK ON
10-bit HEVC HW decode works for **Kodi playback** (rkvdec → NV15 → display plane, zero copy). It does
NOT work for the **streaming re-encode** path: the decoded 10-bit frame is NV15 (10-bit packed) and it
must reach system RAM as 8-bit to feed the encoder — `hwdownload` of NV15 fails with EINVAL (-22) in
the mainline v4l2 ffmpeg (tried nv12, p010le, raw). So 10-bit streams decode in software.
- **The split to bridge:** decode runs in **mainline ffmpeg** (v4l2request, has the NV15 V4L2 path but
  cannot download/convert it here); the **NV15→NV12 resize/convert (RGA / `*_rkrga` filters) lives in
  ffmpeg-rockchip** (`/opt/ffmpeg-rkmpp`, our encoder build). The two are separate binaries joined by a
  RAM pipe, and NV15 cannot make that trip. (Danny's note to verify: "NV15 resizing is in the v4l2
  mainline ffmpeg and not in our encoder ffmpeg" — confirm which build actually has a working NV15
  scale before building on it.)
- **Path to work on:** get NV15→NV12 (with resize) onto the decode side — e.g. a single ffmpeg that
  does v4l2request decode AND rkrga/RGA convert, or add RGA to the decode build, or add an NV15
  download/convert to mainline. Then 10-bit could be HW-decoded and re-encoded, and (if the encoder
  contention is also solved via the chunked path) fully hardware end to end.

### State left on the box
- MPP: **original dual-core restored** (the good one). Single-task copy parked `.singletask-hold`.
- rkvenc driver: carries the harmless `qos_priority` module param (default 0). rebuildable module.
- Service: `default_encoder=x264`, `allow_hw_encoder=False`; page has native `<video controls>` now.

## Known limits / next
- One session for everyone; a new Play anywhere kills the current one.
- Image subtitles (PGS/VobSub) not offered (phase 3 burn-in). ASS styling is flattened to WebVTT.
- Seek restarts the encoder (2-4 s). 10-bit sources cost CPU (SW decode) — fine at 1x pace.
- Encoder single-core (`max_cores=1`) — plenty. Never live-reload `rkvenc`.
- Phase 2: next-episode, watched filter, "continue watching" row, external `.srt` for episodes,
  low-bitrate variant, HEVC variant for Safari, frp bandwidth check.
