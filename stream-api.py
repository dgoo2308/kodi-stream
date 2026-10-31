#!/usr/bin/env python3
"""kodi-stream: on-demand HLS streaming of the Kodi library from the NanoPC-T6.

Design: docs/plan-hls-streaming-service-2026-09-12.md
- catalogue: read-only sqlite on Kodi's MyVideos DB
- ONE session at a time: an ffmpeg pair (mainline decode -> raw NV12 pipe -> ffmpeg-rockchip
  h264_rkmpp encode + HLS mux), paced at real time, rolling window on the NVMe
- direct play for sources that already fit (nginx serves the file via X-Accel-Redirect)
- resume position shared with Kodi (JSON-RPC when Kodi runs, bookmark table otherwise)
Standard library only, like /opt/torrent-api.
"""
import base64
import glob
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CONFIG = {
    "bind": "127.0.0.1",
    "port": 8090,
    "db_glob": "/home/pi/.kodi/userdata/Database/MyVideos*.db",
    "run_dir": "/home/pi/kodi-stream-run",
    "media_root": "/var/media/lacie/Media",      # nginx internal alias /media/ -> this
    "thumb_cache": "/home/pi/kodi-stream-thumbs", # on-disk cache of fetched remote posters
    "thumb_max_age": 31536000,                   # browser/CDN cache lifetime for thumbs (1 year)
    "thumb_tmdb_size": "w342",                   # downsize TMDB posters from 'original' to this
    "ffmpeg_decode": "/usr/local/bin/ffmpeg",    # mainline 8.1: v4l2request HW decode
    "ffprobe": "/usr/local/bin/ffprobe",
    "ffmpeg_encode": "/opt/ffmpeg-rkmpp/bin/ffmpeg",  # ffmpeg-rockchip: h264_rkmpp + hls
    "kodi_rpc": "http://127.0.0.1:8080/jsonrpc",
    "kodi_user": "kodi",
    "kodi_pass": "kodi",
    "direct_max_bitrate": 3500000,
    "hls_time": 4,
    "chunk_lead_seconds": 12,           # HW-encode chunked path: how far ahead of playback to stay
    "hw_decode_codecs": ["h264", "hevc", "vp9", "vp8", "mpeg2video", "av1"],
    "min_mem_available_kb": 800000,
    # Sessions are EVENT playlists that keep every segment until stop, so pause never loses
    # anything and a slow client can buffer ahead. pace_readrate: 0 = encode as fast as the box
    # can (cleanest decode, Nice/CPUWeight keep Kodi first), N = -readrate N. None falls back to
    # the old pace_realtime flag (True = 1x).
    "pace_readrate": None,
    "pace_realtime": False,
    # selectable stream/download quality: name -> [max width, video bitrate, audio bitrate]
    "qualities": {"720p": [1280, "2500k", "128k"], "540p": [960, "1200k", "96k"], "360p": [640, "600k", "64k"]},
    "default_quality": "720p",
    "download_dir": "/home/pi/kodi-stream-dl",  # prepared MP4 downloads (nginx internal alias /dlcache/)
    "download_keep_days": 7,
    "download_max_gb": 30,
    "extra_hw_frames": 12,
    "ffmpeg_x264": "/usr/bin/ffmpeg",  # software libx264 (~1 core @ realtime, 720p)
    "default_encoder": "x264",         # "x264" | "rkmpp". SW encode (x264) is the shipping default;
    "allow_hw_encoder": False,         # HW rkmpp still smears in real playback (DDR contention); chunked
                                       # (pipe or concurrent 2nd input) — unfixable by config/rebuild this
                                       # session (see docs/kodi-stream.md). While False the backend forces
                                       # default_encoder and ignores a client "enc":"rkmpp" request.
    "debug_raw_tee": "",               # debug: directory; when set, the raw NV12 pipe is also written to <dir>/<session>.nv12
}
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
if os.path.exists(CONFIG_PATH):
    CONFIG.update(json.load(open(CONFIG_PATH)))

TEXT_SUBS = {"subrip", "srt", "ass", "ssa", "mov_text", "webvtt", "text"}
EIGHT_BIT = {"yuv420p", "yuvj420p", "nv12", "yuv422p", "yuvj422p"}


def log(msg):
    print(time.strftime("%H:%M:%S"), msg, flush=True)


# ----------------------------------------------------------------------------- catalogue
def db_path():
    paths = sorted(glob.glob(CONFIG["db_glob"]))
    if not paths:
        raise RuntimeError("Kodi video DB not found")
    return paths[-1]


def db():
    con = sqlite3.connect("file:%s?mode=ro" % db_path(), uri=True, timeout=5)
    con.row_factory = sqlite3.Row
    return con


def rows(sql, args=()):
    con = db()
    try:
        return [dict(r) for r in con.execute(sql, args).fetchall()]
    finally:
        con.close()


def has_column(table, col):
    con = db()
    try:
        return col in [r[1] for r in con.execute("pragma table_info(%s)" % table)]
    finally:
        con.close()


MOVIE_VIEW_DEFAULT_FILTER = " AND isDefaultVersion = 1" if has_column("movie_view", "isDefaultVersion") else ""


# sort keys the client may ask for -> fixed ORDER BY clauses (never interpolate client input).
# {a} is the view alias, {y} its premiere-date column. SQLite sorts NULL lowest, so DESC puts it last.
SORTS = {
    "added":   "{a}.dateAdded DESC, {a}.c00 COLLATE NOCASE",
    "title":   "{a}.c00 COLLATE NOCASE",
    "year":    "{y} DESC, {a}.c00 COLLATE NOCASE",
    # votes are 0 for many scrapes (even classics), so only a known-tiny sample (1-19 votes) or a
    # perfect 10 (practically always 1-2 votes) is pushed below the rest instead of topping the list
    "rating":  "coalesce({a}.rating >= 10 OR ({a}.votes > 0 AND {a}.votes < 20), 0), {a}.rating DESC, {a}.c00 COLLATE NOCASE",
    "watched": "{a}.lastPlayed IS NULL, {a}.lastPlayed DESC, {a}.c00 COLLATE NOCASE",
}
MAX_LIMIT = 500


def _catalogue_filters(alias, idcol, media_type, q, genre, unwatched_sql, unwatched):
    """WHERE fragments + args shared by movies() and shows()."""
    where, args = [], []
    if q:
        where.append("%s.c00 LIKE ?" % alias)
        args.append("%%%s%%" % q)
    if genre:
        where.append("EXISTS (SELECT 1 FROM genre_link gl JOIN genre g ON g.genre_id = gl.genre_id"
                     " WHERE gl.media_id = %s.%s AND gl.media_type = '%s' AND g.name = ?)" % (alias, idcol, media_type))
        args.append(genre)
    if unwatched:
        where.append(unwatched_sql)
    return "".join(" AND " + w for w in where), args


def movies(q="", limit=60, offset=0, sort="added", genre="", unwatched=False):
    where, args = _catalogue_filters("m", "idMovie", "movie", q, genre,
                                     "(m.playCount IS NULL OR m.playCount = 0)", unwatched)
    order = SORTS.get(sort, SORTS["added"]).format(a="m", y="m.premiered")
    return _proxy_posters(rows(
        """SELECT m.idMovie AS id, 'movie' AS type, m.idFile, m.c00 AS title,
                  substr(m.premiered,1,4) AS year, m.c11 AS runtime, m.c14 AS genre,
                  round(m.rating, 1) AS rating,
                  m.strPath||m.strFileName AS path,
                  m.resumeTimeInSeconds AS resume, m.totalTimeInSeconds AS total,
                  m.playCount, m.lastPlayed, m.dateAdded,
                  (SELECT url FROM art WHERE media_type='movie' AND media_id=m.idMovie AND type='poster') AS poster
           FROM movie_view m
           WHERE 1=1""" + MOVIE_VIEW_DEFAULT_FILTER + where + """
           ORDER BY """ + order + """
           LIMIT ? OFFSET ?""",
        (*args, max(1, min(limit, MAX_LIMIT)), max(0, offset))))


def shows(q="", limit=100, offset=0, sort="added", genre="", unwatched=False):
    where, args = _catalogue_filters("s", "idShow", "tvshow", q, genre,
                                     "s.watchedcount < s.totalCount", unwatched)
    order = SORTS.get(sort, SORTS["added"]).format(a="s", y="s.c05")
    return _proxy_posters(rows(
        """SELECT s.idShow AS id, 'show' AS type, s.c00 AS title, substr(s.c05,1,4) AS year,
                  s.c08 AS genre, round(s.rating, 1) AS rating,
                  s.totalCount, s.watchedcount, s.totalSeasons, s.dateAdded,
                  (SELECT url FROM art WHERE media_type='tvshow' AND media_id=s.idShow AND type='poster') AS poster
           FROM tvshow_view s
           WHERE 1=1""" + where + """
           ORDER BY """ + order + """
           LIMIT ? OFFSET ?""",
        (*args, max(1, min(limit, MAX_LIMIT)), max(0, offset))))


def genres(media_type):
    """Genres present in the library for 'movie' or 'tvshow', most used first."""
    return rows("""SELECT g.name, count(*) AS count FROM genre g JOIN genre_link gl ON gl.genre_id = g.genre_id
                   WHERE gl.media_type = ? GROUP BY g.name ORDER BY count DESC, g.name""", (media_type,))


def episodes(show_id):
    return _proxy_posters(rows(
        """SELECT e.idEpisode AS id, 'episode' AS type, e.idFile, e.c00 AS title,
                  CAST(e.c12 AS INTEGER) AS season, CAST(e.c13 AS INTEGER) AS episode,
                  e.strTitle AS show, e.strPath||e.strFileName AS path,
                  e.resumeTimeInSeconds AS resume, e.totalTimeInSeconds AS total, e.playCount,
                  (SELECT url FROM art WHERE media_type='episode' AND media_id=e.idEpisode AND type='thumb') AS poster
           FROM episode_view e WHERE e.idShow = ?
           ORDER BY season, episode""",
        (show_id,)))


def item(kind, ident):
    if kind == "movie":
        r = rows("SELECT m.idMovie AS id, 'movie' AS type, m.idFile, m.c00 AS title, substr(m.premiered,1,4) AS year,"
                 " m.strPath||m.strFileName AS path, m.resumeTimeInSeconds AS resume, m.totalTimeInSeconds AS total,"
                 " m.playCount FROM movie_view m WHERE m.idMovie = ?" + MOVIE_VIEW_DEFAULT_FILTER, (ident,))
    elif kind == "episode":
        r = rows("SELECT e.idEpisode AS id, 'episode' AS type, e.idFile, e.c00 AS title, e.strTitle AS show,"
                 " CAST(e.c12 AS INTEGER) AS season, CAST(e.c13 AS INTEGER) AS episode,"
                 " e.strPath||e.strFileName AS path, e.resumeTimeInSeconds AS resume, e.totalTimeInSeconds AS total,"
                 " e.playCount FROM episode_view e WHERE e.idEpisode = ?", (ident,))
    else:
        r = []
    return r[0] if r else None


# ----------------------------------------------------------------------------- thumbnails
# The Kodi art table stores raw poster URLs from mixed hosts (image.tmdb.org,
# assets.fanart.tv, thetvdb.com over http) plus local file paths. Loading those
# straight from the browser means: full-size TMDB originals, http mixed-content
# blocked on the https site, and local paths that don't resolve at all. Instead the
# catalogue hands the client /api/thumb/<kind>/<id>; the box resolves the real URL
# from its own DB (so this is not an open proxy), downsizes TMDB, caches remote
# images on disk once, and serves everything with a 1-year immutable cache.
_ART = {"movie": ("movie", "poster"), "show": ("tvshow", "poster"), "episode": ("episode", "thumb")}


def art_url(kind, ident):
    spec = _ART.get(kind)
    if not spec:
        return None
    r = rows("SELECT url FROM art WHERE media_type=? AND media_id=? AND type=? LIMIT 1",
             (spec[0], ident, spec[1]))
    return r[0]["url"] if r and r[0].get("url") else None


def _proxy_posters(items):
    """Rewrite each row's raw poster URL to the cached /api/thumb endpoint."""
    for it in items:
        it["poster"] = "/api/thumb/%s/%s" % (it["type"], it["id"]) if it.get("poster") else ""
    return items


def _thumb_ext(url):
    ext = os.path.splitext(urllib.parse.urlparse(url).path)[1].lower()
    return ext if ext in (".jpg", ".jpeg", ".png", ".webp", ".gif") else ".jpg"


def _thumb_ctype(ext):
    return {".png": "image/png", ".webp": "image/webp", ".gif": "image/gif"}.get(ext, "image/jpeg")


def ensure_thumb(url):
    """Cache a poster (remote URL or local file) on disk once; return (cache_path,
    content_type) or None. TMDB originals are downsized; local files must sit under the
    media root. Everything ends up in one cache dir so nginx serves it uniformly."""
    remote = url.startswith("http")
    if remote:
        url = re.sub(r"/t/p/(original|w\d+)/", "/t/p/%s/" % CONFIG["thumb_tmdb_size"], url)
    ext = _thumb_ext(url)
    os.makedirs(CONFIG["thumb_cache"], exist_ok=True)
    key = hashlib.sha1(url.encode()).hexdigest() + ext
    path = os.path.join(CONFIG["thumb_cache"], key)
    ctype = _thumb_ctype(ext)
    if os.path.exists(path) and os.path.getsize(path) > 0:
        return path, ctype
    tmp = path + ".tmp"
    if remote:
        req = urllib.request.Request(url, headers={"User-Agent": "kodi-stream/1.0"})
        with urllib.request.urlopen(req, timeout=6) as r:
            ct = r.headers.get("Content-Type", "")
            if not ct.startswith("image/"):
                return None
            # bounded read: some hosts (fanart.tv) trickle from the box; a total deadline
            # makes a stalled fetch fail fast instead of hanging nginx into a 504.
            deadline = time.time() + 15
            buf = bytearray()
            while len(buf) < 8 * 1024 * 1024:
                if time.time() > deadline:
                    raise TimeoutError("thumb fetch budget exceeded")
                chunk = r.read(65536)
                if not chunk:
                    break
                buf += chunk
            data = bytes(buf)
            ctype = ct.split(";")[0] or ctype
        with open(tmp, "wb") as f:
            f.write(data)
    else:
        real = os.path.abspath(url)
        if not (real.startswith(CONFIG["media_root"] + os.sep) and os.path.isfile(real)):
            return None
        shutil.copyfile(real, tmp)
    os.replace(tmp, path)
    return path, ctype


# ----------------------------------------------------------------------------- probing
def ffprobe(path):
    out = subprocess.run(
        [CONFIG["ffprobe"], "-v", "error", "-show_entries",
         "format=format_name,duration,bit_rate:stream=index,codec_type,codec_name,pix_fmt,width,height,"
         "r_frame_rate,avg_frame_rate,bit_rate,channels:stream_tags=language,title",
         "-of", "json", path], capture_output=True, text=True, timeout=30)
    info = json.loads(out.stdout or "{}")
    fmt = info.get("format", {})
    streams = info.get("streams", [])
    video = [s for s in streams if s.get("codec_type") == "video" and s.get("codec_name") not in ("mjpeg", "png")]
    audio = [s for s in streams if s.get("codec_type") == "audio"]
    subs = [s for s in streams if s.get("codec_type") == "subtitle"]
    return {
        "format": fmt.get("format_name", ""),
        "duration": float(fmt.get("duration") or 0),
        "bit_rate": int(fmt.get("bit_rate") or 0),
        "video": video[0] if video else None,
        "audio": [{"index": s["index"], "codec": s.get("codec_name"), "channels": s.get("channels"),
                   "lang": s.get("tags", {}).get("language", ""), "title": s.get("tags", {}).get("title", "")}
                  for s in audio],
        "subs": [{"index": s["index"], "codec": s.get("codec_name"),
                  "lang": s.get("tags", {}).get("language", ""), "title": s.get("tags", {}).get("title", ""),
                  "text": s.get("codec_name") in TEXT_SUBS}
                 for s in subs],
    }


def external_subs(path):
    base = os.path.splitext(path)[0]
    found = []
    for f in sorted(glob.glob(glob.escape(base) + "*.srt")):
        tag = f[len(base):].strip(". ") or "srt"
        found.append({"path": f, "lang": tag[:12], "codec": "subrip", "text": True})
    return found


def parse_fps(s):
    try:
        n, d = s.split("/")
        return float(n) / float(d) if float(d) else 24.0
    except Exception:
        return 24.0


def quality(name):
    """(name, max width, video bitrate, audio bitrate) for a quality name; unknown -> default."""
    qs = CONFIG["qualities"]
    if name not in qs:
        name = CONFIG["default_quality"] if CONFIG["default_quality"] in qs else next(iter(qs))
    w, vb, ab = qs[name]
    return name, int(w), str(vb), str(ab)


def bitrate_bps(s):
    s = str(s).strip().lower()
    mult = 1000 if s.endswith("k") else 1000000 if s.endswith("m") else 1
    return int(float(s.rstrip("km")) * mult)


def pace_args():
    """Decoder input pacing: [] (as fast as possible), -re (1x) or -readrate N."""
    r = CONFIG.get("pace_readrate")
    if r is None:
        r = 1 if CONFIG.get("pace_realtime") else 0
    r = float(r or 0)
    if r <= 0:
        return []
    return ["-re"] if r == 1 else ["-readrate", "%g" % r]


def video_geometry(v, max_w):
    """(out width, out height, fps) for a probed video stream scaled down to max_w."""
    width, height = int(v["width"]), int(v["height"])
    fps = parse_fps(v.get("avg_frame_rate") or v.get("r_frame_rate") or "24")
    if fps <= 0 or fps > 120:
        fps = parse_fps(v.get("r_frame_rate") or "24")
    ow = min(max_w, width) & ~1
    oh = int(round(height * ow / width)) & ~1
    return ow, oh, fps


def default_audio(probe):
    eng = [a for a in probe["audio"] if a["lang"] in ("eng", "en")]
    return (eng or probe["audio"] or [{"index": None}])[0]["index"]


def decide(probe, audio_idx, sub_sel, q=None):
    """Return one of direct / remux / transcode-hw / transcode-sw. A source only passes through
    untouched when it already fits the chosen quality (width and bitrate)."""
    q = q or quality(None)
    v = probe["video"]
    if not v:
        return "transcode-sw"
    codec = v.get("codec_name")
    width = int(v.get("width") or 0)
    eight_bit = v.get("pix_fmt") in EIGHT_BIT
    max_br = min(CONFIG["direct_max_bitrate"], int(bitrate_bps(q[2]) * 1.4))
    fits = codec == "h264" and width <= q[1] and 0 < probe["bit_rate"] <= max_br and eight_bit
    a = next((a for a in probe["audio"] if a["index"] == audio_idx), None)
    container_ok = any(x in probe["format"] for x in ("mp4", "mov"))
    if fits and container_ok and a and a["codec"] == "aac" and not sub_sel:
        return "direct"
    if fits:
        return "remux"
    if codec in CONFIG["hw_decode_codecs"] and eight_bit:
        return "transcode-hw"
    return "transcode-sw"


def transcode_cmds(path, probe, offset, q, mode, enc="x264", pace=()):
    """Stage 1 (decode -> raw NV12 on stdout) and stage 2 (video-only encode -> H.264 mpegts on
    stdout) argv lists, shared by streaming sessions and prepared downloads."""
    v = probe["video"]
    ow, oh, fps = video_geometry(v, q[1])
    ss = ["-ss", "%.3f" % offset] if offset > 0 else []
    hw = mode == "transcode-hw"
    dec = [CONFIG["ffmpeg_decode"], "-nostdin", "-hide_banner", "-loglevel", "warning", *pace,
           # extra_hw_frames: without a deeper V4L2 capture pool the paced HW decoder recycles
           # buffers still in use and hands the encoder torn frames (verified 2026-09-12)
           *(["-hwaccel", "v4l2request", "-hwaccel_output_format", "drm_prime",
              "-extra_hw_frames", str(CONFIG["extra_hw_frames"])] if hw else ["-threads", "8"]),
           *ss, "-i", path, "-map", "0:%d" % v["index"], "-an", "-sn",
           "-vf", ("hwdownload,format=nv12," if hw else "") + "scale=%d:%d" % (ow, oh),
           "-pix_fmt", "nv12", "-f", "rawvideo", "-"]
    gop = str(int(round(fps * 2)))
    if enc == "x264":
        # no -tune zerolatency: sessions are not live any more, lookahead/B-frames buy quality per bit
        vcodec = ["-c:v", "libx264", "-preset", "veryfast", "-b:v", q[2], "-maxrate", q[2],
                  "-bufsize", "%dk" % (2 * bitrate_bps(q[2]) // 1000), "-g", gop, "-profile:v", "high"]
        enc_bin = CONFIG["ffmpeg_x264"]
    else:
        vcodec = ["-c:v", "h264_rkmpp", "-b:v", q[2], "-g", gop, "-profile:v", "high"]
        enc_bin = CONFIG["ffmpeg_encode"]
    # The encoder MUST be single-input: giving the same ffmpeg a second input (the audio demux)
    # concurrently races the h264_rkmpp async DMA input buffers and corrupts the top macroblock
    # rows (verified 2026-09-12). Audio and subtitles are muxed downstream.
    encode = [enc_bin, "-nostdin", "-hide_banner", "-loglevel", "warning",
              "-f", "rawvideo", "-pix_fmt", "nv12", "-s", "%dx%d" % (ow, oh), "-r", "%.3f" % fps, "-i", "pipe:0",
              "-map", "0:0", *vcodec, "-f", "mpegts", "-"]
    return dec, encode


def mem_available_kb():
    with open("/proc/meminfo") as f:
        for line in f:
            if line.startswith("MemAvailable:"):
                return int(line.split()[1])
    return 0


# ----------------------------------------------------------------------------- session
class Session:
    def __init__(self, kind, ident, meta, probe, offset, audio_idx, sub_sel, mode, enc="rkmpp", q=None):
        self.id = "%d" % int(time.time() * 1000)
        self.enc = enc
        self.q = q or quality(None)
        self.kind, self.ident, self.meta, self.probe = kind, ident, meta, probe
        self.offset, self.audio_idx, self.sub_sel, self.mode = offset, audio_idx, sub_sel, mode
        self.dir = os.path.join(CONFIG["run_dir"], self.id)
        self.procs = []
        self.started = time.time()
        self.error = None
        self.chunked = False       # HW-encode path: sequential decode->RAM->encode per segment
        self.stop_flag = False
        self.producer = None       # producer thread for the chunked path

    def info(self):
        produced = 0.0
        complete = False
        pl = os.path.join(self.dir, "stream_0.m3u8")
        if os.path.exists(pl):
            try:
                with open(pl) as f:
                    txt = f.read()
                produced = sum(float(x) for x in re.findall(r"#EXTINF:([0-9.]+)", txt))
                seq = re.search(r"#EXT-X-MEDIA-SEQUENCE:(\d+)", txt)
                if seq:
                    produced += int(seq.group(1)) * CONFIG["hls_time"]
                complete = "#EXT-X-ENDLIST" in txt
            except Exception:
                pass
        alive = (self.chunked and self.producer is not None and self.producer.is_alive()) \
            or any(p.poll() is None for p in self.procs)
        return {"session": self.id, "type": self.kind, "id": self.ident, "title": self.meta.get("title"),
                "mode": self.mode, "enc": self.enc, "quality": self.q[0], "offset": self.offset,
                "duration": self.probe["duration"], "produced": self.offset + produced, "complete": complete,
                "alive": alive, "error": self.error,
                "ready": os.path.exists(os.path.join(self.dir, "master.m3u8")),
                "url": "/hls/%s/master.m3u8" % self.id, "uptime": int(time.time() - self.started)}

    def stop(self):
        self.stop_flag = True
        for p in reversed(self.procs):
            if p.poll() is None:
                p.terminate()
        deadline = time.time() + 3
        for p in self.procs:
            while p.poll() is None and time.time() < deadline:
                time.sleep(0.1)
            if p.poll() is None:
                p.kill()
        if self.producer is not None:
            self.producer.join(timeout=4)
        for f in ("/dev/shm/kstream_%s.nv12" % self.id, "/dev/shm/kstream_%s.ts" % self.id):
            try:
                os.remove(f)
            except OSError:
                pass
        shutil.rmtree(self.dir, ignore_errors=True)


class SessionManager:
    def __init__(self):
        self.lock = threading.Lock()
        self.current = None
        os.makedirs(CONFIG["run_dir"], exist_ok=True)
        for d in glob.glob(os.path.join(CONFIG["run_dir"], "*")):
            shutil.rmtree(d, ignore_errors=True)

    def start(self, kind, ident, offset, audio_idx, sub_sel, enc="rkmpp", qname=None):
        meta = item(kind, ident)
        if not meta:
            raise ValueError("unknown item")
        path = meta["path"]
        if not os.path.exists(path):
            raise ValueError("file not available: %s" % path)
        probe = ffprobe(path)
        if not probe["video"]:
            raise ValueError("no video stream")
        if audio_idx is None:
            audio_idx = default_audio(probe)
        q = quality(qname)
        mode = decide(probe, audio_idx, sub_sel, q)
        with self.lock:
            if self.current:
                self.current.stop()
                self.current = None
            if mode == "direct":
                rel = os.path.relpath(path, CONFIG["media_root"])
                return {"mode": "direct", "url": "/api/direct/%s/%s" % (kind, ident), "offset": 0,
                        "duration": probe["duration"], "title": meta["title"], "path": rel}
            if mode == "transcode-sw" and mem_available_kb() < CONFIG["min_mem_available_kb"]:
                raise RuntimeError("not enough free memory for a software-decode session")
            s = Session(kind, ident, meta, probe, offset, audio_idx, sub_sel, mode, enc, q)
            os.makedirs(s.dir)
            self._launch(s, path)
            self.current = s
            return s.info()

    def _run_step(self, s, cmd, logf):
        """Run one ffmpeg step to completion, tracking it so stop() can kill it."""
        logf.write("STEP: %s\n" % " ".join(cmd))
        logf.flush()
        p = subprocess.Popen(cmd, stdout=logf, stderr=logf)
        s.procs = [x for x in s.procs if x.poll() is None] + [p]
        while p.poll() is None:
            if s.stop_flag:
                p.terminate()
                try:
                    p.wait(timeout=3)
                except Exception:
                    p.kill()
                return -1
            time.sleep(0.05)
        return p.returncode

    def _launch_chunked(self, s, path):
        """HW encode without DDR contention: per HLS segment, decode a chunk into RAM
        (/dev/shm, decoder only), then HW-encode that buffer (encoder only), then mux
        audio (CPU only). Decode and encode never overlap, so the encoder never reads a
        starved memory bus -> no top-row smear. Sequential rate is ~6x, paced to ~1x."""
        v = s.probe["video"]
        ow, oh, fps = video_geometry(v, s.q[1])
        SEG = float(CONFIG["hls_time"])
        gop = str(int(round(fps * 2)))
        hw = s.mode == "transcode-hw"
        logf = open(os.path.join(s.dir, "ffmpeg.log"), "w", buffering=1)
        vraw = "/dev/shm/kstream_%s.nv12" % s.id
        vts = "/dev/shm/kstream_%s.ts" % s.id
        s.chunked = True
        paced = bool(pace_args())
        lead = CONFIG.get("chunk_lead_seconds", 12)
        dur_total = s.probe["duration"]

        def write_playlist(window, seq, final=False):
            lines = ["#EXTM3U", "#EXT-X-VERSION:6",
                     "#EXT-X-TARGETDURATION:%d" % int(round(SEG + 1)),
                     "#EXT-X-MEDIA-SEQUENCE:%d" % seq, "#EXT-X-PLAYLIST-TYPE:EVENT",
                     "#EXT-X-INDEPENDENT-SEGMENTS"]
            for name, dur in window:
                lines.append("#EXTINF:%.3f," % dur)
                lines.append(name)
            if final:
                lines.append("#EXT-X-ENDLIST")
            tmp = os.path.join(s.dir, "stream_0.m3u8.tmp")
            with open(tmp, "w") as f:
                f.write("\n".join(lines) + "\n")
            os.replace(tmp, os.path.join(s.dir, "stream_0.m3u8"))

        def write_master():
            br = bitrate_bps(s.q[2]) + bitrate_bps(s.q[3])
            with open(os.path.join(s.dir, "master.m3u8"), "w") as f:
                f.write("#EXTM3U\n#EXT-X-VERSION:6\n"
                        "#EXT-X-STREAM-INF:BANDWIDTH=%d,RESOLUTION=%dx%d,CODECS=\"avc1.64001f,mp4a.40.2\"\n"
                        "stream_0.m3u8\n" % (br, ow, oh))

        def producer():
            seg = 0
            seq = 0
            window = []
            try:
                while not s.stop_flag:
                    t0 = s.offset + seg * SEG
                    if dur_total and t0 >= dur_total - 0.1:
                        write_playlist(window, seq, final=True)
                        break
                    seglen = min(SEG, dur_total - t0) if dur_total else SEG
                    # 1) decode chunk -> RAM (decoder only)
                    dec = [CONFIG["ffmpeg_decode"], "-nostdin", "-hide_banner", "-loglevel", "warning",
                           *(["-hwaccel", "v4l2request", "-hwaccel_output_format", "drm_prime",
                              "-extra_hw_frames", str(CONFIG["extra_hw_frames"])] if hw else ["-threads", "8"]),
                           "-ss", "%.3f" % t0, "-i", path, "-t", "%.3f" % (seglen + 0.05),
                           "-map", "0:%d" % v["index"], "-an", "-sn",
                           "-vf", ("hwdownload,format=nv12," if hw else "") + "scale=%d:%d" % (ow, oh),
                           "-pix_fmt", "nv12", "-f", "rawvideo", "-y", vraw]
                    if self._run_step(s, dec, logf) != 0:
                        write_playlist(window, seq, final=True)
                        break
                    # 2) encode RAM -> RAM (encoder ONLY: no concurrent DMA -> no smear)
                    enc = [CONFIG["ffmpeg_encode"], "-nostdin", "-hide_banner", "-loglevel", "warning",
                           "-f", "rawvideo", "-pix_fmt", "nv12", "-s", "%dx%d" % (ow, oh),
                           "-r", "%.3f" % fps, "-i", vraw, "-map", "0:0",
                           "-c:v", "h264_rkmpp", "-b:v", s.q[2], "-g", gop,
                           "-profile:v", "high", "-f", "mpegts", "-y", vts]
                    if self._run_step(s, enc, logf) != 0:
                        if not s.stop_flag:
                            s.error = "encode failed"
                        break
                    # 3) mux video(copy) + audio(aac) -> segment (CPU only, no HW encoder running)
                    segname = "seg_0_%05d.ts" % seg
                    # audio bounded to the chunk (+small margin) so we don't mux the rest of the film;
                    # -shortest ends the segment when the 4s video (copy) ends
                    a_in = ["-ss", "%.3f" % t0, "-t", "%.3f" % (seglen + 0.3), "-i", path] if s.audio_idx is not None else []
                    a_map = ["-map", "1:%d" % s.audio_idx] if s.audio_idx is not None else []
                    a_c = ["-c:a", "aac", "-b:a", s.q[3], "-ac", "2", "-shortest"] if s.audio_idx is not None else []
                    mux = [CONFIG["ffmpeg_decode"], "-nostdin", "-hide_banner", "-loglevel", "warning",
                           "-i", vts, *a_in, "-map", "0:v:0", *a_map, "-c:v", "copy", *a_c,
                           "-muxpreload", "0", "-muxdelay", "0", "-output_ts_offset", "%.3f" % (seg * SEG),
                           "-f", "mpegts", "-y", os.path.join(s.dir, segname)]
                    if self._run_step(s, mux, logf) != 0:
                        if not s.stop_flag:
                            s.error = "mux failed"
                        break
                    window.append((segname, seglen))
                    if seg == 0:
                        write_master()
                    write_playlist(window, seq)
                    seg += 1
                    # pace: keep ~lead seconds of content ahead of real-time playback
                    if paced:
                        ahead = (seg * SEG) - (time.time() - s.started)
                        target = time.time() + max(0.0, ahead - lead)
                        while time.time() < target and not s.stop_flag:
                            time.sleep(0.2)
            except Exception as e:
                s.error = "chunked producer: %s" % e
            finally:
                for f in (vraw, vts):
                    try:
                        os.remove(f)
                    except OSError:
                        pass

        s.producer = threading.Thread(target=producer, daemon=True)
        s.producer.start()

    def _launch(self, s, path):
        if s.enc == "rkmpp" and s.mode in ("transcode-hw", "transcode-sw"):
            return self._launch_chunked(s, path)
        v = s.probe["video"]
        logf = open(os.path.join(s.dir, "ffmpeg.log"), "w")
        ss = ["-ss", "%.3f" % s.offset] if s.offset > 0 else []
        pace = pace_args()
        # audio / subtitle mapping on the encoder side (input 1 = source file, input 2 = external srt)
        enc_inputs = ["-i", path]
        maps = ["-map", "1:%d" % s.audio_idx] if s.audio_idx is not None else ["-an"]
        sub_args, var_map = [], "v:0,a:0"
        if s.sub_sel:
            if str(s.sub_sel).startswith("ext:"):
                enc_inputs += ["-i", str(s.sub_sel)[4:]]
                maps += ["-map", "2:0"]
            else:
                maps += ["-map", "1:%d" % int(s.sub_sel)]
            sub_args = ["-c:s", "webvtt"]
            var_map = "v:0,a:0,s:0,sgroup:subs"
        # EVENT playlist: every segment stays until the session stops (a rolling window deleted
        # the segments a paused viewer had not reached yet, and players then jumped to the live edge)
        hls = ["-f", "hls", "-hls_time", str(CONFIG["hls_time"]), "-hls_list_size", "0",
               "-hls_playlist_type", "event", "-hls_flags", "independent_segments", "-hls_segment_type", "mpegts",
               "-master_pl_name", "master.m3u8", "-var_stream_map", var_map,
               "-hls_segment_filename", "seg_%v_%05d.ts", "stream_%v.m3u8"]
        audio = ["-c:a", "aac", "-b:a", s.q[3], "-ac", "2"] if s.audio_idx is not None else []
        if s.mode == "remux":
            cmd = [CONFIG["ffmpeg_encode"], "-nostdin", "-hide_banner", "-loglevel", "warning", *pace, *ss,
                   "-i", path, *(["-i", str(s.sub_sel)[4:]] if str(s.sub_sel).startswith("ext:") else []),
                   "-map", "0:%d" % v["index"], *[m.replace("1:", "0:").replace("2:0", "1:0") for m in maps],
                   "-c:v", "copy", *audio, *sub_args, *hls]
            s.procs.append(subprocess.Popen(cmd, cwd=s.dir, stdout=logf, stderr=logf))
            return
        # Stages 1+2 — decode -> raw NV12 pipe -> video-only encode -> H.264 mpegts pipe
        dec, enc = transcode_cmds(path, s.probe, s.offset, s.q, s.mode, s.enc, pace)
        # Stage 3 — mux encoded video (copy) + audio (AAC) + subtitles (WebVTT) into HLS. Mainline
        # ffmpeg, no MPP. Input 0 = encoded video from the pipe; input 1 = source file (audio +
        # embedded subs), seeked to the offset so it aligns with the already-offset video.
        mss = ["-ss", "%.3f" % s.offset] if s.offset > 0 else []
        mux_inputs = ["-i", "pipe:0", *mss, "-i", path]
        mux_maps = ["-map", "0:v:0"]
        if s.audio_idx is not None:
            mux_maps += ["-map", "1:%d" % s.audio_idx]
        if s.sub_sel:
            if str(s.sub_sel).startswith("ext:"):
                mux_inputs += ["-i", str(s.sub_sel)[4:]]
                mux_maps += ["-map", "2:0"]
            else:
                mux_maps += ["-map", "1:%d" % int(s.sub_sel)]
        mux = [CONFIG["ffmpeg_decode"], "-nostdin", "-hide_banner", "-loglevel", "warning",
               "-fflags", "+genpts", *mux_inputs, *mux_maps,
               "-c:v", "copy", *audio, *sub_args, *hls]
        logf.write("DEC: %s\nENC: %s\nMUX: %s\n" % (" ".join(dec), " ".join(enc), " ".join(mux)))
        logf.flush()
        p1 = subprocess.Popen(dec, stdout=subprocess.PIPE, stderr=logf)
        src = p1.stdout
        tee = None
        if CONFIG["debug_raw_tee"]:   # debug: capture what the encoder receives
            tee = subprocess.Popen(["tee", os.path.join(CONFIG["debug_raw_tee"], s.id + ".nv12")],
                                   stdin=p1.stdout, stdout=subprocess.PIPE, stderr=logf)
            p1.stdout.close()
            src = tee.stdout
        p2 = subprocess.Popen(enc, stdin=src, stdout=subprocess.PIPE, stderr=logf)
        src.close()
        p3 = subprocess.Popen(mux, stdin=p2.stdout, cwd=s.dir, stdout=logf, stderr=logf)
        p2.stdout.close()
        s.procs += [p1, p2, p3] + ([tee] if tee else [])

    def status(self):
        with self.lock:
            return self.current.info() if self.current else {"session": None}

    def stop(self):
        with self.lock:
            if self.current:
                self.current.stop()
                self.current = None


# ----------------------------------------------------------------------------- downloads
def display_title(meta):
    if meta.get("type") == "episode":
        return "%s S%02dE%02d %s" % (meta.get("show") or "", int(meta.get("season") or 0),
                                     int(meta.get("episode") or 0), meta.get("title") or "")
    return "%s (%s)" % (meta["title"], meta["year"]) if meta.get("year") else meta["title"]


def attachment(filename):
    """Content-Disposition for a download: ASCII fallback + RFC 5987 UTF-8 name."""
    ascii_name = re.sub(r'[^A-Za-z0-9 ._()\-]+', "", filename).strip() or "video"
    return "attachment; filename=\"%s\"; filename*=UTF-8''%s" % (ascii_name, urllib.parse.quote(filename))


class DownloadManager:
    """Prepared MP4 downloads for offline viewing. Jobs queue up and ONE background worker encodes
    them at the lowest CPU priority into download_dir (whole file, unpaced, +faststart); nginx
    serves finished files through the internal /dlcache/ alias. Finished jobs survive a restart via
    a .json sidecar; old files are pruned by age and by total size."""

    def __init__(self):
        self.dir = CONFIG["download_dir"]
        self.lock = threading.Lock()
        self.wake = threading.Event()
        self.jobs = {}          # name -> job; dict order = queue order
        self.procs = []
        self.cancel = None      # name of the running job to abort
        os.makedirs(self.dir, exist_ok=True)
        for f in glob.glob(os.path.join(self.dir, "*.part.mp4")) + glob.glob(os.path.join(self.dir, "*.log")):
            os.remove(f)
        for side in sorted(glob.glob(os.path.join(self.dir, "*.json")), key=os.path.getmtime):
            try:
                job = json.load(open(side))
            except Exception:
                job = {}
            if job.get("name") and os.path.exists(os.path.join(self.dir, job["name"])):
                self.jobs[job["name"]] = job
            else:
                os.remove(side)
        threading.Thread(target=self._worker, daemon=True).start()

    def _path(self, name, ext=""):
        return os.path.join(self.dir, name + ext)

    def add(self, kind, ident, qname, audio_idx, sub_sel):
        meta = item(kind, ident)
        if not meta:
            raise ValueError("unknown item")
        if not os.path.exists(meta["path"]):
            raise ValueError("file not available")
        q = quality(qname)
        sub = ("_s" + hashlib.sha1(str(sub_sel).encode()).hexdigest()[:6]) if sub_sel else ""
        name = "%s_%d_%s_a%s%s.mp4" % (kind, ident, q[0], "" if audio_idx is None else int(audio_idx), sub)
        title = display_title(meta)
        with self.lock:
            job = self.jobs.get(name)
            if job and job["state"] != "error":
                return dict(job)
            job = {"name": name, "type": kind, "id": ident, "title": title, "quality": q[0],
                   "audio": audio_idx, "sub": sub_sel, "state": "queued", "progress": 0.0, "error": None,
                   "note": "", "created": time.time(), "filename": "%s (%s).mp4" % (title, q[0])}
            self.jobs.pop(name, None)
            self.jobs[name] = job
        self.wake.set()
        return dict(job)

    def list(self):
        self._housekeep()
        out = []
        with self.lock:
            for job in self.jobs.values():
                j = dict(job)
                if j["state"] == "done":
                    try:
                        j["size"] = os.path.getsize(self._path(j["name"]))
                    except OSError:
                        j["size"] = 0
                    j["url"] = "/api/download/file/" + j["name"]
                out.append(j)
        return out[::-1]   # newest first

    def get_done(self, name):
        with self.lock:
            job = self.jobs.get(name)
            return dict(job) if job and job["state"] == "done" else None

    def delete(self, name):
        with self.lock:
            job = self.jobs.pop(name, None)
            if job and job["state"] == "running":
                self.cancel = name
                for p in self.procs:
                    if p.poll() is None:
                        p.kill()
        if not job:   # only names of known jobs ever touch the disk
            return False
        for ext in ("", ".json", ".log"):
            try:
                os.remove(self._path(name, ext))
            except OSError:
                pass
        return job is not None

    def _housekeep(self):
        cutoff = time.time() - CONFIG["download_keep_days"] * 86400
        with self.lock:
            done = [j for j in self.jobs.values() if j["state"] == "done"]
        sizes = {}
        for j in done:
            try:
                sizes[j["name"]] = os.path.getsize(self._path(j["name"]))
            except OSError:
                sizes[j["name"]] = 0
        total = sum(sizes.values())
        for j in sorted(done, key=lambda j: j.get("finished") or j["created"]):
            if (j.get("finished") or j["created"]) < cutoff or total > CONFIG["download_max_gb"] * 1e9:
                log("download prune %s" % j["name"])
                self.delete(j["name"])
                total -= sizes[j["name"]]

    def _worker(self):
        while True:
            self.wake.wait(60)
            self.wake.clear()
            while True:
                with self.lock:
                    job = next((j for j in self.jobs.values() if j["state"] == "queued"), None)
                if not job:
                    break
                if mem_available_kb() < CONFIG["min_mem_available_kb"]:
                    job["note"] = "waiting for free memory"
                    time.sleep(15)
                    continue
                job.update(state="running", note="", progress=0.0)
                try:
                    self._run(job)
                except Exception as e:
                    job.update(state="error", error=str(e))
                    log("download %s failed: %r" % (job["name"], e))

    def _run(self, job):
        meta = item(job["type"], job["id"])
        path = meta["path"]
        probe = ffprobe(path)
        if not probe["video"]:
            raise ValueError("no video stream")
        q = quality(job["quality"])
        audio_idx = job["audio"] if job["audio"] is not None else default_audio(probe)
        sub_sel = job["sub"]
        mode = decide(probe, audio_idx, sub_sel, q)
        dur = probe["duration"] or 1.0
        tmp = self._path(job["name"][:-4], ".part.mp4")
        logf = open(self._path(job["name"], ".log"), "w")
        nice = ["nice", "-n", "19"]
        ext_sub = str(sub_sel)[4:] if sub_sel and str(sub_sel).startswith("ext:") else None
        copy = mode in ("direct", "remux")   # already fits this quality: no video re-encode
        # input 0 = video (the source file, or the encoded pipe); src = index of the source file input
        inputs = ["-i", path] if copy else ["-i", "pipe:0", "-i", path]
        src = 0 if copy else 1
        maps = ["-map", "0:%d" % probe["video"]["index"]] if copy else ["-map", "0:v:0"]
        if audio_idx is not None:
            maps += ["-map", "%d:%d" % (src, int(audio_idx))]
        if sub_sel:
            if ext_sub:
                inputs += ["-i", ext_sub]
                maps += ["-map", "%d:0" % (src + 1)]
            else:
                maps += ["-map", "%d:%d" % (src, int(sub_sel))]
        mux = [*nice, CONFIG["ffmpeg_decode"], "-nostdin", "-hide_banner", "-loglevel", "warning",
               "-progress", "pipe:1", "-nostats", "-fflags", "+genpts", *inputs, *maps, "-c:v", "copy",
               *(["-c:a", "aac", "-b:a", q[3], "-ac", "2"] if audio_idx is not None else []),
               *(["-c:s", "mov_text"] if sub_sel else []),
               "-movflags", "+faststart", "-f", "mp4", "-y", tmp]
        with self.lock:
            self.cancel = None
            if copy:
                procs = [subprocess.Popen(mux, stdout=subprocess.PIPE, stderr=logf, text=True)]
            else:
                dec, enc = transcode_cmds(path, probe, 0, q, mode, "x264")
                logf.write("DEC: %s\nENC: %s\n" % (" ".join(dec), " ".join(enc)))
                p1 = subprocess.Popen(nice + dec, stdout=subprocess.PIPE, stderr=logf)
                p2 = subprocess.Popen(nice + enc, stdin=p1.stdout, stdout=subprocess.PIPE, stderr=logf)
                p1.stdout.close()
                p3 = subprocess.Popen(mux, stdin=p2.stdout, stdout=subprocess.PIPE, stderr=logf, text=True)
                p2.stdout.close()
                procs = [p1, p2, p3]
            self.procs = procs
        logf.write("MUX: %s\n" % " ".join(mux))
        logf.flush()
        for line in procs[-1].stdout:   # -progress key=value lines
            if line.startswith("out_time_us=") and line[12:].strip().isdigit():
                job["progress"] = min(0.999, int(line[12:]) / 1e6 / dur)
        rcs = [p.wait() for p in procs]
        logf.close()
        if self.cancel == job["name"]:
            try:
                os.remove(tmp)
            except OSError:
                pass
            return
        if any(rcs) or not os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass
            raise RuntimeError("ffmpeg exit %s (see %s.log)" % (rcs, job["name"]))
        os.replace(tmp, self._path(job["name"]))
        os.remove(self._path(job["name"], ".log"))
        job.update(state="done", progress=1.0, finished=time.time())
        with open(self._path(job["name"], ".json"), "w") as f:
            json.dump(job, f)
        log("download ready %s (%s)" % (job["name"], mode))


# ----------------------------------------------------------------------------- resume sync
def kodi_rpc(method, params):
    req = urllib.request.Request(CONFIG["kodi_rpc"], data=json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        headers={"Content-Type": "application/json",
                 "Authorization": "Basic " + base64.b64encode(("%s:%s" % (CONFIG["kodi_user"], CONFIG["kodi_pass"])).encode()).decode()})
    with urllib.request.urlopen(req, timeout=3) as r:
        return json.loads(r.read().decode())


def save_progress(kind, ident, position, duration):
    meta = item(kind, ident)
    if not meta:
        return {"ok": False, "error": "unknown item"}
    finished = duration and position >= 0.9 * duration
    resume = {"position": 0 if finished else int(position), "total": int(duration or meta.get("total") or 0)}
    try:
        kodi_rpc("JSONRPC.Ping", {})
        method = "VideoLibrary.SetMovieDetails" if kind == "movie" else "VideoLibrary.SetEpisodeDetails"
        params = {("movieid" if kind == "movie" else "episodeid"): ident, "resume": resume}
        if finished:
            params["playcount"] = int(meta.get("playCount") or 0) + 1
        kodi_rpc(method, params)
        return {"ok": True, "via": "kodi", "resume": resume}
    except Exception as e:
        # Kodi not running: write Kodi's bookmark row directly (type 1 = resume point)
        con = sqlite3.connect(db_path(), timeout=5)
        try:
            con.execute("DELETE FROM bookmark WHERE idFile=? AND type=1", (meta["idFile"],))
            if not finished:
                con.execute("INSERT INTO bookmark (idFile,timeInSeconds,totalTimeInSeconds,thumbNailImage,player,playerState,type)"
                            " VALUES (?,?,?,?,?,?,1)", (meta["idFile"], float(position), float(resume["total"]), "", "VideoPlayer", ""))
            else:
                con.execute("UPDATE files SET playCount=COALESCE(playCount,0)+1 WHERE idFile=?", (meta["idFile"],))
            con.execute("UPDATE files SET lastPlayed=datetime('now','localtime') WHERE idFile=?", (meta["idFile"],))
            con.commit()
            return {"ok": True, "via": "sqlite", "resume": resume, "kodi_error": str(e)}
        finally:
            con.close()


# ----------------------------------------------------------------------------- thumb prewarm
def warm_thumbs():
    """Background: fill the thumbnail cache for the browse grids (movies + shows) so live
    requests are cache hits. Flaky hosts (fanart.tv trickles from the box) get one retry."""
    time.sleep(5)
    try:
        items = movies("", 100000, 0) + shows("", 100000, 0)
    except Exception as e:
        log("thumb prewarm: catalogue failed: %r" % e)
        return
    cached = missed = 0
    for it in items:
        if not it.get("poster"):
            continue
        raw = art_url(it["type"], it["id"])
        if not raw:
            continue
        for attempt in (1, 2):
            try:
                if ensure_thumb(raw):
                    cached += 1
                break
            except Exception:
                if attempt == 2:
                    missed += 1
                time.sleep(1)
        time.sleep(0.05)
    log("thumb prewarm done: cached=%d missed=%d of %d" % (cached, missed, len(items)))


# ----------------------------------------------------------------------------- http
SESSIONS = SessionManager()
DOWNLOADS = DownloadManager()


class Handler(BaseHTTPRequestHandler):
    server_version = "kodi-stream/0.1"

    def log_message(self, fmt, *args):
        log("%s %s" % (self.address_string(), fmt % args))

    def send_json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n).decode() or "{}") if n else {}

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        p = u.path
        try:
            if p == "/api/health":
                return self.send_json({"ok": True, "db": os.path.basename(db_path()), "session": SESSIONS.status(),
                                       "mem_available_kb": mem_available_kb()})
            if p in ("/api/movies", "/api/shows"):
                arg = lambda k, d="": q.get(k, [d])[0]
                fn = movies if p == "/api/movies" else shows
                return self.send_json(fn(arg("q"), int(arg("limit", 60)), int(arg("offset", 0)),
                                         arg("sort", "added"), arg("genre"), arg("unwatched") == "1"))
            if p == "/api/genres":
                return self.send_json(genres("tvshow" if q.get("type", ["movie"])[0] in ("tvshow", "show") else "movie"))
            m = re.match(r"^/api/shows/(\d+)/episodes$", p)
            if m:
                return self.send_json(episodes(int(m.group(1))))
            m = re.match(r"^/api/item/(movie|episode)/(\d+)$", p)
            if m:
                meta = item(m.group(1), int(m.group(2)))
                if not meta:
                    return self.send_json({"error": "not found"}, 404)
                available = os.path.exists(meta["path"])
                probe = ffprobe(meta["path"]) if available else None
                if probe:
                    probe["subs"] += external_subs(meta["path"])
                    v = probe.pop("video")
                    probe["video"] = {"codec": v.get("codec_name"), "width": v.get("width"), "height": v.get("height"),
                                      "pix_fmt": v.get("pix_fmt"), "index": v.get("index")} if v else None
                meta.update({"available": available, "probe": probe,
                             "size": os.path.getsize(meta["path"]) if available else 0,
                             "qualities": list(CONFIG["qualities"]), "default_quality": quality(None)[0]})
                return self.send_json(meta)
            m = re.match(r"^/api/(direct|download/original)/(movie|episode)/(\d+)$", p)
            if m:
                meta = item(m.group(2), int(m.group(3)))
                if not meta or not os.path.exists(meta["path"]):
                    return self.send_json({"error": "not found"}, 404)
                rel = os.path.relpath(meta["path"], CONFIG["media_root"])
                self.send_response(200)
                if m.group(1) == "direct":
                    self.send_header("Content-Type", "video/mp4")
                else:
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Disposition", attachment(os.path.basename(meta["path"])))
                self.send_header("X-Accel-Redirect", "/media/" + urllib.parse.quote(rel))
                self.end_headers()
                return
            if p == "/api/downloads":
                du = shutil.disk_usage(CONFIG["download_dir"])
                return self.send_json({"jobs": DOWNLOADS.list(), "free_gb": round(du.free / 1e9, 1)})
            m = re.match(r"^/api/download/file/([\w.-]+\.mp4)$", p)
            if m:
                job = DOWNLOADS.get_done(m.group(1))
                if not job:
                    return self.send_json({"error": "not found"}, 404)
                self.send_response(200)
                self.send_header("Content-Type", "video/mp4")
                self.send_header("Content-Disposition", attachment(job["filename"]))
                self.send_header("X-Accel-Redirect", "/dlcache/" + urllib.parse.quote(job["name"]))
                self.end_headers()
                return
            m = re.match(r"^/api/thumb/(movie|show|episode)/(\d+)$", p)
            if m:
                raw = art_url(m.group(1), int(m.group(2)))
                got = None
                if raw:
                    try:
                        got = ensure_thumb(raw)
                    except Exception as e:
                        log("thumb %s failed: %r" % (raw[:80], e))
                if not got:
                    return self.send_json({"error": "no art"}, 404)
                cpath, ctype = got
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Cache-Control", "public, max-age=%d, immutable" % CONFIG["thumb_max_age"])
                self.send_header("X-Accel-Redirect", "/thumbcache/" + urllib.parse.quote(os.path.basename(cpath)))
                self.end_headers()
                return
            if p == "/api/session":
                return self.send_json(SESSIONS.status())
            return self.send_json({"error": "not found"}, 404)
        except Exception as e:
            log("GET %s failed: %r" % (p, e))
            return self.send_json({"error": str(e)}, 500)

    def do_POST(self):
        p = urllib.parse.urlparse(self.path).path
        try:
            body = self.read_json()
            if p == "/api/play":
                res = SESSIONS.start(body["type"], int(body["id"]), float(body.get("offset") or 0),
                                     body.get("audio"), body.get("sub") or None,
                                     (body.get("enc") if (CONFIG.get("allow_hw_encoder") and body.get("enc") in ("x264", "rkmpp"))
                                      else CONFIG["default_encoder"]), body.get("quality"))
                return self.send_json(res)
            if p == "/api/download":
                return self.send_json(DOWNLOADS.add(body["type"], int(body["id"]), body.get("quality"),
                                                    body.get("audio"), body.get("sub") or None))
            if p == "/api/download/delete":
                return self.send_json({"ok": DOWNLOADS.delete(str(body.get("name") or ""))})
            if p == "/api/stop":
                SESSIONS.stop()
                return self.send_json({"ok": True})
            if p == "/api/progress":
                return self.send_json(save_progress(body["type"], int(body["id"]),
                                                    float(body.get("position") or 0), float(body.get("duration") or 0)))
            return self.send_json({"error": "not found"}, 404)
        except Exception as e:
            log("POST %s failed: %r" % (p, e))
            return self.send_json({"error": str(e)}, 500)


if __name__ == "__main__":
    log("kodi-stream on %s:%d, db %s, run dir %s" % (CONFIG["bind"], CONFIG["port"], db_path(), CONFIG["run_dir"]))
    threading.Thread(target=warm_thumbs, daemon=True).start()
    ThreadingHTTPServer((CONFIG["bind"], CONFIG["port"]), Handler).serve_forever()
