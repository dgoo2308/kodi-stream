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
    "ffmpeg_decode": "/usr/local/bin/ffmpeg",    # mainline 8.1: v4l2request HW decode
    "ffprobe": "/usr/local/bin/ffprobe",
    "ffmpeg_encode": "/opt/ffmpeg-rkmpp/bin/ffmpeg",  # ffmpeg-rockchip: h264_rkmpp + hls
    "kodi_rpc": "http://127.0.0.1:8080/jsonrpc",
    "kodi_user": "kodi",
    "kodi_pass": "kodi",
    "max_width": 1280,
    "video_bitrate": "2500k",
    "audio_bitrate": "128k",
    "direct_max_bitrate": 3500000,
    "hls_time": 4,
    "hls_list_size": 8,
    "chunk_lead_seconds": 12,           # HW-encode chunked path: how far ahead of playback to stay
    "hw_decode_codecs": ["h264", "hevc", "vp9", "vp8", "mpeg2video", "av1"],
    "min_mem_available_kb": 800000,
    "pace_realtime": True,
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


def movies(q="", limit=60, offset=0):
    like = "%%%s%%" % q if q else ""
    return rows(
        """SELECT m.idMovie AS id, 'movie' AS type, m.idFile, m.c00 AS title,
                  substr(m.premiered,1,4) AS year, m.c11 AS runtime,
                  m.strPath||m.strFileName AS path,
                  m.resumeTimeInSeconds AS resume, m.totalTimeInSeconds AS total,
                  m.playCount, m.lastPlayed, m.dateAdded,
                  (SELECT url FROM art WHERE media_type='movie' AND media_id=m.idMovie AND type='poster') AS poster
           FROM movie_view m
           WHERE (? = '' OR m.c00 LIKE ?)""" + MOVIE_VIEW_DEFAULT_FILTER + """
           ORDER BY CASE WHEN ? = '' THEN m.dateAdded END DESC, m.c00
           LIMIT ? OFFSET ?""",
        (q, like, q, limit, offset))


def shows(q="", limit=100, offset=0):
    like = "%%%s%%" % q if q else ""
    return rows(
        """SELECT s.idShow AS id, 'show' AS type, s.c00 AS title, substr(s.c05,1,4) AS year,
                  s.totalCount, s.watchedcount, s.totalSeasons,
                  (SELECT url FROM art WHERE media_type='tvshow' AND media_id=s.idShow AND type='poster') AS poster
           FROM tvshow_view s WHERE (? = '' OR s.c00 LIKE ?)
           ORDER BY s.c00 LIMIT ? OFFSET ?""",
        (q, like, limit, offset))


def episodes(show_id):
    return rows(
        """SELECT e.idEpisode AS id, 'episode' AS type, e.idFile, e.c00 AS title,
                  CAST(e.c12 AS INTEGER) AS season, CAST(e.c13 AS INTEGER) AS episode,
                  e.strTitle AS show, e.strPath||e.strFileName AS path,
                  e.resumeTimeInSeconds AS resume, e.totalTimeInSeconds AS total, e.playCount,
                  (SELECT url FROM art WHERE media_type='episode' AND media_id=e.idEpisode AND type='thumb') AS poster
           FROM episode_view e WHERE e.idShow = ?
           ORDER BY season, episode""",
        (show_id,))


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


def decide(probe, audio_idx, sub_sel):
    """Return one of direct / remux / transcode-hw / transcode-sw."""
    v = probe["video"]
    if not v:
        return "transcode-sw"
    codec = v.get("codec_name")
    width = int(v.get("width") or 0)
    eight_bit = v.get("pix_fmt") in EIGHT_BIT
    fits = codec == "h264" and width <= CONFIG["max_width"] and 0 < probe["bit_rate"] <= CONFIG["direct_max_bitrate"] and eight_bit
    a = next((a for a in probe["audio"] if a["index"] == audio_idx), None)
    container_ok = any(x in probe["format"] for x in ("mp4", "mov"))
    if fits and container_ok and a and a["codec"] == "aac" and not sub_sel:
        return "direct"
    if fits:
        return "remux"
    if codec in CONFIG["hw_decode_codecs"] and eight_bit:
        return "transcode-hw"
    return "transcode-sw"


def mem_available_kb():
    with open("/proc/meminfo") as f:
        for line in f:
            if line.startswith("MemAvailable:"):
                return int(line.split()[1])
    return 0


# ----------------------------------------------------------------------------- session
class Session:
    def __init__(self, kind, ident, meta, probe, offset, audio_idx, sub_sel, mode, enc="rkmpp"):
        self.id = "%d" % int(time.time() * 1000)
        self.enc = enc
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
        pl = os.path.join(self.dir, "stream_0.m3u8")
        if os.path.exists(pl):
            try:
                with open(pl) as f:
                    txt = f.read()
                produced = sum(float(x) for x in re.findall(r"#EXTINF:([0-9.]+)", txt))
                seq = re.search(r"#EXT-X-MEDIA-SEQUENCE:(\d+)", txt)
                if seq:
                    produced += int(seq.group(1)) * CONFIG["hls_time"]
            except Exception:
                pass
        alive = (self.chunked and self.producer is not None and self.producer.is_alive()) \
            or any(p.poll() is None for p in self.procs)
        return {"session": self.id, "type": self.kind, "id": self.ident, "title": self.meta.get("title"),
                "mode": self.mode, "enc": self.enc, "offset": self.offset, "duration": self.probe["duration"],
                "produced": self.offset + produced, "alive": alive, "error": self.error,
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

    def start(self, kind, ident, offset, audio_idx, sub_sel, enc="rkmpp"):
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
            eng = [a for a in probe["audio"] if a["lang"] in ("eng", "en")]
            audio_idx = (eng or probe["audio"] or [{"index": None}])[0]["index"]
        mode = decide(probe, audio_idx, sub_sel)
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
            s = Session(kind, ident, meta, probe, offset, audio_idx, sub_sel, mode, enc)
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
        width, height = int(v["width"]), int(v["height"])
        fps = parse_fps(v.get("avg_frame_rate") or v.get("r_frame_rate") or "24")
        if fps <= 0 or fps > 120:
            fps = parse_fps(v.get("r_frame_rate") or "24")
        ow = min(CONFIG["max_width"], width) & ~1
        oh = int(round(height * ow / width)) & ~1
        SEG = float(CONFIG["hls_time"])
        gop = str(int(round(fps * 2)))
        hw = s.mode == "transcode-hw"
        logf = open(os.path.join(s.dir, "ffmpeg.log"), "w", buffering=1)
        vraw = "/dev/shm/kstream_%s.nv12" % s.id
        vts = "/dev/shm/kstream_%s.ts" % s.id
        s.chunked = True
        keep = CONFIG["hls_list_size"]
        paced = CONFIG["pace_realtime"]
        lead = CONFIG.get("chunk_lead_seconds", 12)
        dur_total = s.probe["duration"]

        def write_playlist(window, seq, final=False):
            lines = ["#EXTM3U", "#EXT-X-VERSION:6",
                     "#EXT-X-TARGETDURATION:%d" % int(round(SEG + 1)),
                     "#EXT-X-MEDIA-SEQUENCE:%d" % seq, "#EXT-X-INDEPENDENT-SEGMENTS"]
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
            br = 0
            try:
                br = int(str(CONFIG["video_bitrate"]).rstrip("kK")) * 1000 + 128000
            except ValueError:
                br = 2600000
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
                           "-c:v", "h264_rkmpp", "-b:v", CONFIG["video_bitrate"], "-g", gop,
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
                    a_c = ["-c:a", "aac", "-b:a", CONFIG["audio_bitrate"], "-ac", "2", "-shortest"] if s.audio_idx is not None else []
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
                    if paced and len(window) > keep:
                        old, _ = window.pop(0)
                        try:
                            os.remove(os.path.join(s.dir, old))
                        except OSError:
                            pass
                        seq += 1
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
        width, height = int(v["width"]), int(v["height"])
        fps = parse_fps(v.get("avg_frame_rate") or v.get("r_frame_rate") or "24")
        if fps <= 0 or fps > 120:
            fps = parse_fps(v.get("r_frame_rate") or "24")
        ow = min(CONFIG["max_width"], width) & ~1
        oh = int(round(height * ow / width)) & ~1
        logf = open(os.path.join(s.dir, "ffmpeg.log"), "w")
        ss = ["-ss", "%.3f" % s.offset] if s.offset > 0 else []
        pace = ["-re"] if CONFIG["pace_realtime"] else []
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
        # paced (default): rolling window. Unpaced: keep the session's segments until stop (the
        # HW blocks run at full speed, which scored cleanest), still nothing kept after stop.
        window = (["-hls_list_size", str(CONFIG["hls_list_size"]), "-hls_flags", "delete_segments+independent_segments"]
                  if CONFIG["pace_realtime"] else ["-hls_list_size", "0", "-hls_flags", "independent_segments"])
        hls = ["-f", "hls", "-hls_time", str(CONFIG["hls_time"]), *window, "-hls_segment_type", "mpegts",
               "-master_pl_name", "master.m3u8", "-var_stream_map", var_map,
               "-hls_segment_filename", "seg_%v_%05d.ts", "stream_%v.m3u8"]
        audio = ["-c:a", "aac", "-b:a", CONFIG["audio_bitrate"], "-ac", "2"] if s.audio_idx is not None else []
        if s.mode == "remux":
            cmd = [CONFIG["ffmpeg_encode"], "-nostdin", "-hide_banner", "-loglevel", "warning", *pace, *ss,
                   "-i", path, *(["-i", str(s.sub_sel)[4:]] if str(s.sub_sel).startswith("ext:") else []),
                   "-map", "0:%d" % v["index"], *[m.replace("1:", "0:").replace("2:0", "1:0") for m in maps],
                   "-c:v", "copy", *audio, *sub_args, *hls]
            s.procs.append(subprocess.Popen(cmd, cwd=s.dir, stdout=logf, stderr=logf))
            return
        hw = s.mode == "transcode-hw"
        dec = [CONFIG["ffmpeg_decode"], "-nostdin", "-hide_banner", "-loglevel", "warning", *pace,
               # extra_hw_frames: without a deeper V4L2 capture pool the paced HW decoder recycles
               # buffers still in use and hands the encoder torn frames (verified 2026-09-12)
               *(["-hwaccel", "v4l2request", "-hwaccel_output_format", "drm_prime",
                  "-extra_hw_frames", str(CONFIG["extra_hw_frames"])] if hw else ["-threads", "8"]),
               *ss, "-i", path, "-map", "0:%d" % v["index"], "-an", "-sn",
               "-vf", ("hwdownload,format=nv12," if hw else "") + "scale=%d:%d" % (ow, oh),
               "-pix_fmt", "nv12", "-f", "rawvideo", "-"]
        if s.enc == "x264":
            vcodec = ["-c:v", "libx264", "-preset", "veryfast", "-tune", "zerolatency", "-b:v", CONFIG["video_bitrate"],
                      "-maxrate", CONFIG["video_bitrate"], "-bufsize", "5M", "-g", str(int(round(fps * 2))), "-profile:v", "high"]
            enc_bin = CONFIG["ffmpeg_x264"]
        else:
            vcodec = ["-c:v", "h264_rkmpp", "-b:v", CONFIG["video_bitrate"], "-g", str(int(round(fps * 2))), "-profile:v", "high"]
            enc_bin = CONFIG["ffmpeg_encode"]
        # Stage 2 — VIDEO-ONLY encode to a raw H.264/mpegts pipe. The encoder MUST be single-input:
        # giving the same ffmpeg a second input (the audio demux) concurrently races the h264_rkmpp
        # async DMA input buffers and corrupts the top macroblock rows (smear on motion) — verified
        # 2026-09-12: raw-in clean, video-only encode clean, video+audio encode streaks. Audio and
        # subtitles are muxed downstream in stage 3, which never drives the HW encoder.
        enc = [enc_bin, "-nostdin", "-hide_banner", "-loglevel", "warning",
               "-f", "rawvideo", "-pix_fmt", "nv12", "-s", "%dx%d" % (ow, oh), "-r", "%.3f" % fps, "-i", "pipe:0",
               "-map", "0:0", *vcodec, "-f", "mpegts", "-"]
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


# ----------------------------------------------------------------------------- http
SESSIONS = SessionManager()


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
            if p == "/api/movies":
                return self.send_json(movies(q.get("q", [""])[0], int(q.get("limit", [60])[0]), int(q.get("offset", [0])[0])))
            if p == "/api/shows":
                return self.send_json(shows(q.get("q", [""])[0], int(q.get("limit", [100])[0]), int(q.get("offset", [0])[0])))
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
                meta.update({"available": available, "probe": probe})
                return self.send_json(meta)
            m = re.match(r"^/api/direct/(movie|episode)/(\d+)$", p)
            if m:
                meta = item(m.group(1), int(m.group(2)))
                if not meta or not os.path.exists(meta["path"]):
                    return self.send_json({"error": "not found"}, 404)
                rel = os.path.relpath(meta["path"], CONFIG["media_root"])
                self.send_response(200)
                self.send_header("Content-Type", "video/mp4")
                self.send_header("X-Accel-Redirect", "/media/" + urllib.parse.quote(rel))
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
                                      else CONFIG["default_encoder"]))
                return self.send_json(res)
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
    ThreadingHTTPServer((CONFIG["bind"], CONFIG["port"]), Handler).serve_forever()
