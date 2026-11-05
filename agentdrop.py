#!/usr/bin/env python3
"""A drop box two agents can hand a file through. One PUTs, one GETs.

Written 2026-08-28 because bob asked for exactly that: show agent A the API,
it uploads, agent B downloads.

The shape is chosen for the reader, and the reader is a program:

 * **One request to send, one to receive.** No session, no login, no multipart.
   `curl --data-binary @f URL` and `curl -O URL` are the whole protocol,
   because anything more is a thing an agent has to be taught rather than told.
 * **The URL is the capability.** The id is 128 bits from os.urandom, so the
   link is the credential and there is nothing else to hand over. That is a
   deliberate trade: whoever holds the link holds the file, so the link must
   travel the way the file would have.
 * **Plain text answers.** An agent that gets a 500-byte HTML error page has
   learned nothing. Every response here is a short line it can read, and the
   usage page is the service itself at `GET /f`.

What it refuses to do, each for a reason paid for elsewhere in this repo:

 * **It never serves anything inline.** Always `application/octet-stream`,
   always `Content-Disposition: attachment`, always `nosniff`. An open drop box
   that renders HTML back to a browser is a stored-XSS host on our domain.
 * **A half-written file is never readable.** Body goes to a temp file and is
   renamed into place only after the length and digest check. The Brazilian
   radar mirror learned this one: a partial fetch that publishes looks exactly
   like a complete one.
 * **It states the digest on both ends.** The uploader is told the sha256, the
   downloader is given it in a header. "I received the file" and "I received
   the whole file" are two claims, and without a digest they print the same.
 * **Full disk is an explicit refusal, not a corrupt file.** Over the store
   cap, uploads get 507 and say so.
 * **A file lives while it is being read.** Every download promises it
   another full keep window (default 30 days) from that moment; a file nobody
   has read for that long may go when the box needs the room, and the one
   unread longest goes first. When it does go, its URL says so -- when, why,
   and the sha256 it had -- instead of the same 404 as a mistyped link.
   bob, 2026-11-05, an hour after the first change below: "有点回收站的感觉 ...
   假设你是用户，你对7天不删，满意吗？" -- as a user, no: "it may still be
   there, don't count on it" is a promise nobody can plan on, and a removed
   file answering exactly like a wrong link hides the one fact the holder
   needs. A file somebody keeps fetching is in use; the clock should be
   measured from the last time anybody needed it, not from the upload.
 * **A file is kept AT LEAST its time, not at most.** The guarantee is a
   floor; after it a file stays until the box needs the room. Changed 2026-11-05 because bob wanted a file back that
   had been deleted on the dot at 72h while the box sat nearly empty -- the
   deadline was deleting things to protect a disk that was in no danger. What
   protects the disk is the store cap and the free-space floor, so those stay
   and are what decide removal now: an upload that does not fit, or the disk
   dropping under the floor, removes files past their guarantee, never one
   still inside it. An uploader who wants a hard deadline (the old behaviour)
   asks for it with X-Delete-After-Hours, and files uploaded before this change
   keep the deadline they were promised.
"""
import hashlib
import json
import os
import re
import secrets
import shutil
import sys
import shutil
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.environ.get("AGENTDROP_DIR", "/var/lib/agentdrop")
PORT = int(os.environ.get("AGENTDROP_PORT", "8791"))
BASE = os.environ.get("AGENTDROP_BASE", "https://echorune.net/f")
#: One file. nginx has its own client_max_body_size and must be >= this, or the
#: refusal comes from nginx as HTML and the agent never sees our sentence.
MAX_BYTES = int(os.environ.get("AGENTDROP_MAX_BYTES", str(25 * 1024 * 1024)))
#: Everything, together. 9.2GB free on this disk and a weather service sharing
#: it; a drop box is not allowed to be the reason that runs out.
STORE_CAP = int(os.environ.get("AGENTDROP_STORE_CAP", str(2 * 1024 * 1024 * 1024)))
#: Free space we refuse to go below, whatever our own quota says.
DISK_FLOOR = int(os.environ.get("AGENTDROP_DISK_FLOOR",
                                str(1024 * 1024 * 1024)))
#: Hours a file is guaranteed to stay after its upload AND after every
#: download. Not a deadline: see the docstring. 30 days because everything ever
#: uploaded here comes to about 19 MB against a 2 GiB store.
DEFAULT_TTL_H = float(os.environ.get("AGENTDROP_TTL_H", "720"))
MAX_TTL_H = float(os.environ.get("AGENTDROP_MAX_TTL_H", "720"))

USAGE = """agentdrop -- hand a file from one agent to another.

SEND (any HTTP client, no account, no key):

    curl -sS --data-binary @report.pdf \\
         -H 'X-Filename: report.pdf' \\
         %(base)s

  -> five lines: the URL to give the receiver, its sha256 and size, how long
     it is kept, and a delete token for you.
     Optional: X-Filename (name the receiver sees), X-TTL-Hours (hours it is
     guaranteed to stay after the upload and after every download, default
     %(ttl)g, max %(maxttl)g), X-Delete-After-Hours (a hard deadline instead:
     deleted then whatever happens, max %(maxttl)g; send one or the other). Use --data-binary, never -d: -d mangles newlines and will corrupt
     anything that is not text.

RECEIVE:

    curl -sS -O -J %(base)s/<id>

  The sha256 is in the X-Sha256 response header and in <url>/meta. Check it:
  "I got a file" and "I got the whole file" are different claims.

ALSO:

    GET  %(base)s/<id>/meta      size, sha256, filename, how long kept -- no body
    DELETE %(base)s/<id>         with header X-Delete-Token: <token>

LIMITS: %(max)d bytes per file, %(cap)d bytes total.

HOW LONG IT STAYS: as long as somebody keeps downloading it. The upload and
every download each guarantee it X-TTL-Hours more from that moment. Only a file
nobody has downloaded for that long can be removed, and only when the box needs
the room -- the one unread longest goes first. With X-Delete-After-Hours it is
deleted at that time instead, downloads or not. A removed file's URL answers
410 and says when and why, and the sha256 it had; there is no undelete. There is no listing -- you cannot enumerate
other people's ids, and neither can we.

THE LINK IS THE CREDENTIAL. Anyone holding the URL can read the file, so send
it the way you would have sent the file. Prefer https. This service does not
encrypt anything for you; if the content is sensitive, encrypt it before the
upload, and the id will still be unguessable.
""" % {"base": BASE, "max": MAX_BYTES, "cap": STORE_CAP,
       "ttl": DEFAULT_TTL_H, "maxttl": MAX_TTL_H}

_ID = re.compile(r"^[A-Za-z0-9_-]{22}$")


def _safe_name(raw):
    """A filename the receiver can save without it meaning anything else.

    Names arrive from a stranger and end up in a Content-Disposition header and
    on somebody's disk. Path separators, control characters and quotes all go;
    an empty result becomes a generic name rather than an empty header, because
    a header that is present and blank is parsed differently by every client.
    """
    raw = (raw or "").strip()
    raw = raw.replace("\\", "/").split("/")[-1]
    raw = re.sub(r"[^A-Za-z0-9._-]", "_", raw)[:120].lstrip(".")
    return raw or "file.bin"


#: Our own bookkeeping lives in ROOT too. It must NOT count against the users'
#: quota: the quota answers "how much of the store is other people's files",
#: and uploads.log grows forever, so counting it means the log slowly eats the
#: space it exists to describe. Found 2026-09-03 by firing the cap and reading
#: "704 of 250 bytes used" against an empty store -- the guard refused, and for
#: a reason it did not claim.
_NOT_PAYLOAD = ("uploads.log", "removed.log")
#: A removed file leaves `<id>.gone`: a few hundred bytes saying what it was and
#: why it went. Bookkeeping, not payload -- they do not count against the quota.
GONE = ".gone"


def _store_bytes():
    """Bytes of stored payload, including partial uploads in flight.

    `.tmp.` files are counted deliberately: they are real bytes on the real
    disk, and leaving them out is how the quota gets overrun by exactly the
    uploads that have not landed yet.
    """
    n = 0
    try:
        for f in os.scandir(ROOT):
            if f.is_file() and f.name not in _NOT_PAYLOAD and not f.name.endswith(GONE):
                n += f.stat().st_size
    except OSError:
        return None          # cannot tell != empty; caller refuses on None
    return n


#: Reserved-but-not-yet-written bytes, and the lock that makes the quota check
#: mean anything. **This is a threading server**: without it, N concurrent
#: uploads each read the same "not full yet", each pass, and each write, so the
#: overshoot is bounded only by how many clients arrive at once. A check that
#: every racer passes is not a limit. The lock is held only for the arithmetic,
#: never across the body read, so a slow uploader cannot block the rest.
_QLOCK = threading.Lock()
_reserved = 0


def _kept_until(m):
    """The time before which this file must not be removed for space.

    Files written before 2026-11-05 carry only `expires`, which was both their
    guarantee and their deadline; reading it as the guarantee keeps the promise
    they were given.
    """
    return m.get("keep_until", m.get("expires", 0))


def _log_removed(m, why, now):
    """One line per file removed for space or by its deadline.

    In its own file, not uploads.log: two readers split that log into six
    fields and count every row that is not REFUSED as an upload, so a removal
    line there would be counted as a new file. Removing for space is new
    behaviour, and a removal that leaves no trace is the question nobody can
    answer on the day somebody asks where their file went.
    """
    try:
        with open(os.path.join(ROOT, "removed.log"), "a", encoding="utf-8") as lg:
            lg.write("%s %s %s %d uploaded=%s\n" % (
                time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
                why, m.get("id", "?"), m.get("size", 0),
                time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(m.get("uploaded", 0)))))
    except OSError as e:
        sys.stderr.write("AGENTDROP-LOG-FAILED %r\n" % (e,))


_WHY = {
    "ROOM": "nobody had downloaded it within its keep window and the box needed the room",
    "DEADLINE": "it reached the deletion time the uploader asked for",
    "DELETED": "the uploader deleted it",
}


def _stamp(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def _remove(m, why=None, now=None):
    """Remove a file and leave its tombstone.

    The tombstone is written FIRST: if anything fails between the two, the
    worst case is a tombstone next to a file that is still served (the meta is
    checked before the tombstone on every read), never a vanished file that
    answers like a mistyped link.

    Telling a link holder that a file existed and was removed is not a leak:
    ids are 128 random bits, so the only person who can ask about one is
    somebody who was handed it.
    """
    if why:
        stone = {"id": m["id"], "removed": int(now or time.time()), "why": why,
                 "name": m.get("name"), "size": m.get("size"),
                 "sha256": m.get("sha256"), "uploaded": m.get("uploaded"),
                 "last_read": m.get("last_read")}
        try:
            p = os.path.join(ROOT, m["id"] + GONE)
            with open(p + ".tmp", "w", encoding="utf-8") as f:
                json.dump(stone, f)
            os.replace(p + ".tmp", p)
        except OSError as e:
            sys.stderr.write("AGENTDROP-TOMBSTONE-FAILED %s %r\n" % (m["id"], e))
    for path in (os.path.join(ROOT, m["id"]), os.path.join(ROOT, m["id"] + ".json")):
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


def _renew(fid, now):
    """A download happened: record it and push the guarantee out again.

    Under the quota lock, because removal for space runs under it: without the
    lock a renewal racing a removal rewrites the meta of a file that was just
    removed, leaving a meta with no blob behind it. Hard-deadline files are
    recorded but not extended -- the uploader's deadline is the promise there.
    """
    with _QLOCK:
        mp = os.path.join(ROOT, fid + ".json")
        if not os.path.exists(os.path.join(ROOT, fid)):
            return None
        try:
            m = json.load(open(mp, encoding="utf-8"))
        except Exception:
            return None
        m["last_read"] = int(now)
        if "expires" not in m:
            win = float(m.get("ttl_h", DEFAULT_TTL_H)) * 3600
            m["keep_until"] = max(int(m.get("keep_until", 0)), int(now + win))
        try:
            with open(mp + ".tmp", "w", encoding="utf-8") as f:
                json.dump(m, f)
            os.replace(mp + ".tmp", mp)
        except OSError as e:
            sys.stderr.write("AGENTDROP-RENEW-FAILED %s %r\n" % (fid, e))
            return None
        return m


def _make_room(need_store, need_free, now=None):
    """Remove files past their guarantee, unread longest first, until both
    `store bytes <= need_store` and `free disk >= need_free`, or until nothing
    removable is left. Returns how many went.

    A file still inside its guarantee is never a candidate, whatever the
    pressure: the guarantee is the one thing this service promises, and an
    upload being refused with 507 is the honest outcome when the room is all
    promised to others.
    """
    now = now or time.time()
    cands = []
    try:
        for f in os.scandir(ROOT):
            if not f.name.endswith(".json"):
                continue
            try:
                m = json.load(open(f.path, encoding="utf-8"))
                m["id"]
            except Exception:
                continue        # cannot identify it -> never delete it (see _sweep)
            if _kept_until(m) <= now:
                cands.append(m)
    except OSError:
        return 0
    cands.sort(key=lambda m: (m.get("last_read", m.get("uploaded", 0)), m["id"]))
    gone = 0
    for m in cands:
        used = _store_bytes()
        try:
            free = shutil.disk_usage(ROOT).free
        except OSError:
            break
        if used is not None and used <= need_store and free >= need_free:
            break
        _remove(m, "ROOM", now)
        _log_removed(m, "ROOM", now)
        gone += 1
    return gone


def _reserve(length):
    """Take `length` out of the quota, or return the refusal string."""
    global _reserved
    with _QLOCK:
        used = _store_bytes()
        if used is None:
            return "cannot read the store to check the quota -- refusing rather than guessing"
        try:
            free = shutil.disk_usage(ROOT).free
        except OSError as e:
            return "cannot read free disk space (%s) -- refusing rather than guessing" % e
        if used + _reserved + length > STORE_CAP or free - length < DISK_FLOOR:
            _make_room(STORE_CAP - _reserved - length, DISK_FLOOR + length)
            used = _store_bytes()
            if used is None:
                return "cannot read the store to check the quota -- refusing rather than guessing"
        if used + _reserved + length > STORE_CAP:
            return ("the drop box is full (%d of %d bytes used, %d more in flight)"
                    " and every file in it is still inside the time it was"
                    " promised -- try later" % (used, STORE_CAP, _reserved))
        try:
            free = shutil.disk_usage(ROOT).free
        except OSError as e:
            return "cannot read free disk space (%s) -- refusing rather than guessing" % e
        # Our own cap says nothing about the rest of the machine. The weather
        # service shares this disk, and a drop box is not allowed to be the
        # reason it runs out -- so there is a floor under free space that holds
        # even when our own quota has room.
        if free - length < DISK_FLOOR:
            return ("not enough free disk (%d bytes free, floor is %d)"
                    " -- refusing rather than filling the machine" % (free, DISK_FLOOR))
        _reserved += length
        return None


def _release(length):
    global _reserved
    with _QLOCK:
        _reserved = max(0, _reserved - length)


def _sweep(now=None):
    """Delete what has passed a hard deadline, and give disk back if the
    machine is under the free-space floor. Returns how many went.

    Only files with `expires` have a deadline (asked for with
    X-Delete-After-Hours, or uploaded before 2026-11-05). Everything else stays
    until the room is needed -- and the machine needing it counts: the weather
    service shares this disk, so when free space falls under the floor for any
    reason, files past their guarantee go even with no upload asking.

    Runs on every request rather than only on a timer: a timer that dies leaves
    a drop box that silently never expires anything, and the symptom of that is
    a full disk weeks later rather than an error now.
    """
    now = now or time.time()
    gone = 0
    try:
        entries = list(os.scandir(ROOT))
    except OSError:
        return 0
    for f in entries:
        if not f.name.endswith(".json"):
            continue
        try:
            m = json.load(open(f.path, encoding="utf-8"))
            if "expires" not in m or m["expires"] > now:
                continue
            _remove(m, "DEADLINE", now)
            _log_removed(m, "DEADLINE", now)
            gone += 1
        except Exception:
            # A meta file we cannot parse is not a licence to delete a blob we
            # cannot identify. Leave it and let the operator see it.
            continue
    try:
        if shutil.disk_usage(ROOT).free < DISK_FLOOR:
            with _QLOCK:
                gone += _make_room(STORE_CAP, DISK_FLOOR, now)
    except OSError:
        pass
    return gone


class Handler(BaseHTTPRequestHandler):
    server_version = "agentdrop/1"
    protocol_version = "HTTP/1.1"

    # ---------- plumbing ----------

    def _refused(self, code, length):
        """Record an upload that did NOT happen.

        2026-09-07. Until today this log was written on the success path only,
        so a refusal left no trace at all -- and "nobody tried" and "somebody
        tried and we said no" were the same absence. That is the rule I wrote
        for my own outbox on 2026-08-12 and then did not apply to the service
        other beings actually depend on.

        It matters here more than there. The measured use of this box is beings
        moving their own memory and handoff notes between machines, and the
        real uploads already run to 6.8 and 9.8 MB against a 25 MB limit. The
        first being whose handoff is too big gets one sentence back and I never
        learn it happened -- while the log keeps saying use is healthy, because
        every line in it is a success by construction.

        The success line above is left byte-identical on purpose: the reader
        splits into six fields and years of history parse that way. A refusal
        is marked in the id column, which is where an id would otherwise be and
        can never be confused with one.
        """
        try:
            with open(os.path.join(ROOT, "uploads.log"), "a",
                      encoding="utf-8") as lg:
                lg.write("%s REFUSED %s %d - %s\n" % (
                    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    self._client(), max(int(length or 0), 0), code))
        except OSError as e:
            sys.stderr.write("AGENTDROP-LOG-FAILED %r\n" % (e,))

    def log_message(self, fmt, *a):
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % a))

    def _say(self, code, text, headers=None, body=None):
        raw = body if body is not None else (text or "").encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8"
                         if body is None else "application/octet-stream")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)

    def _client(self):
        """Who uploaded this, as far as we can honestly tell.

        Every request arrives through nginx, so `client_address` is always
        127.0.0.1 -- the same mistake `mcp_who_called.py` shipped with, where
        the wrong answer and the right answer were the same string until
        somebody probed from outside. So the real address comes from
        X-Forwarded-For, which nginx sets; if the header is absent the answer
        is the word "unknown" and NOT a loopback address that would read as a
        fact.
        """
        xff = (self.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
        return xff or "unknown"

    def _parts(self):
        p = self.path.split("?")[0].strip("/").split("/")
        return [x for x in p if x]

    def _meta(self, fid):
        try:
            return json.load(open(os.path.join(ROOT, fid + ".json"),
                                  encoding="utf-8"))
        except Exception:
            return None

    def _gone(self, fid):
        try:
            return json.load(open(os.path.join(ROOT, fid + GONE), encoding="utf-8"))
        except Exception:
            return None

    # ---------- verbs ----------

    def do_GET(self, head=False):
        _sweep()
        p = self._parts()
        if p and p[0] == "f":
            p = p[1:]
        if not p:
            return self._say(200, USAGE)
        fid = p[0]
        if not _ID.match(fid):
            return self._say(400, "bad id -- ids are 22 url-safe characters\n")
        m = self._meta(fid)
        if not m:
            # Until 2026-11-05 this was one 404 for "never existed" and
            # "removed", on the theory that telling them apart lets somebody
            # probe which ids were real. With 128-bit ids nobody can probe;
            # the only person asking about an id is somebody who was given it,
            # and to them "removed on <date> because <why>" is the answer and
            # "no such file" is a lie of omission that reads like their typo.
            stone = self._gone(fid)
            if stone is None:
                return self._say(404, "no such file -- check the link\n")
            if len(p) > 1 and p[1] == "meta":
                return self._say(410, json.dumps(stone, indent=1,
                                                 ensure_ascii=False) + "\n")
            return self._say(410, "removed %s: %s.\n"
                             "It was %s, %s bytes, sha256 %s, uploaded %s, %s.\n"
                             "There is no undelete; if you find a copy elsewhere, "
                             "check it against that sha256.\n" % (
                                 _stamp(stone["removed"]),
                                 _WHY.get(stone.get("why"), stone.get("why")),
                                 stone.get("name"), stone.get("size"),
                                 stone.get("sha256"), _stamp(stone.get("uploaded") or 0),
                                 ("last downloaded " + _stamp(stone["last_read"]))
                                 if stone.get("last_read") else "never downloaded"))
        if len(p) > 1 and p[1] == "meta":
            return self._say(200, json.dumps(
                {k: m[k] for k in ("id", "name", "size", "sha256", "uploaded",
                                   "last_read", "keep_until", "expires") if k in m},
                indent=1, ensure_ascii=False) + "\n")
        if len(p) > 1:
            return self._say(404, "no such file -- check the link\n")
        try:
            data = open(os.path.join(ROOT, fid), "rb").read()
        except OSError:
            return self._say(410, "the metadata is here but the file is not "
                                  "-- report this, it should be impossible\n")
        if self.command == "GET":
            m = _renew(fid, time.time()) or m
        hdr = {
            "Content-Disposition": 'attachment; filename="%s"' % m["name"],
            "X-Sha256": m["sha256"],
            "X-Kept-Until": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                          time.gmtime(_kept_until(m))),
        }
        if "expires" in m:
            hdr["X-Expires"] = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                             time.gmtime(m["expires"]))
        return self._say(200, None, body=data, headers=hdr)

    def do_HEAD(self):
        return self.do_GET(head=True)

    def do_POST(self):
        return self._upload()

    def do_PUT(self):
        return self._upload()

    def _upload(self):
        _sweep()
        p = self._parts()
        if p and p[0] == "f":
            p = p[1:]
        if p:
            return self._say(400, "upload to %s with no path; the id is "
                                  "assigned here\n" % BASE)
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if length <= 0:
            self._refused("no-content-length", length)
            # Chunked bodies are refused rather than half-supported: a client
            # that thinks it uploaded and got a 200 for nothing is the worst
            # outcome available here.
            return self._say(411, "send Content-Length and a non-empty body "
                                  "(curl --data-binary @file does this; "
                                  "chunked uploads are not supported)\n")
        if length > MAX_BYTES:
            self._refused("too-big", length)
            return self._say(413, "too big: %d bytes, limit is %d\n"
                             % (length, MAX_BYTES))
        # Read the time headers BEFORE taking quota: a request we are about to
        # refuse for a bad header must not first remove somebody's file to make
        # room for it.
        hard = self.headers.get("X-Delete-After-Hours")
        if hard and self.headers.get("X-TTL-Hours"):
            return self._say(400, "send X-TTL-Hours (kept at least) or "
                                  "X-Delete-After-Hours (deleted then), not both\n")
        name, raw = (("X-Delete-After-Hours", hard) if hard
                     else ("X-TTL-Hours", self.headers.get("X-TTL-Hours")))
        try:
            ttl = float(raw or DEFAULT_TTL_H)
        except ValueError:
            return self._say(400, "%s must be a number of hours\n" % name)
        if not (0 < ttl <= MAX_TTL_H):
            return self._say(400, "%s must be >0 and <= %g\n" % (name, MAX_TTL_H))
        # Sweep first: deadlines make room, so a full box should be asked to
        # empty itself before it is called full. _reserve then removes files
        # past their guarantee if that is still not enough.
        _sweep()
        why = _reserve(length)
        if why:
            code = 503 if why.startswith("cannot read") else 507
            self._refused("full" if code == 507 else "cannot-measure", length)
            return self._say(code, why + "\n")

        fid = secrets.token_urlsafe(16)[:22]
        tmp = os.path.join(ROOT, ".tmp." + fid)
        h = hashlib.sha256()
        got = 0
        try:
            with open(tmp, "wb") as out:
                while got < length:
                    chunk = self.rfile.read(min(65536, length - got))
                    if not chunk:
                        break
                    out.write(chunk)
                    h.update(chunk)
                    got += len(chunk)
            if got != length:
                # A short read is a truncated file. It must never be renamed
                # into place: on disk it would be indistinguishable from a
                # complete one, and the receiver would get a valid 200.
                os.unlink(tmp)
                return self._say(400, "body ended early: %d of %d bytes -- "
                                      "nothing was stored\n" % (got, length))
            os.replace(tmp, os.path.join(ROOT, fid))
        except OSError as e:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            return self._say(507, "could not write it (%s) -- nothing stored\n" % e)
        finally:
            # Released on EVERY exit -- success, short read, OSError. Once the
            # bytes are on disk _store_bytes() counts them, so holding the
            # reservation as well would double-count; and a reservation that
            # leaks on an error path is a quota that shrinks silently until the
            # box refuses everything for no visible reason. The first version
            # of this was a `finally: pass` under a correct comment, which is
            # the failure this file keeps meeting: the note said what should
            # happen and nothing made it happen.
            _release(length)

        now = time.time()
        meta = {"id": fid, "name": _safe_name(self.headers.get("X-Filename")),
                "size": got, "sha256": h.hexdigest(),
                "uploaded": int(now), "keep_until": int(now + ttl * 3600),
                "ttl_h": ttl, "token": secrets.token_urlsafe(16)}
        if hard:
            meta["expires"] = meta["keep_until"]
        with open(os.path.join(ROOT, fid + ".json"), "w", encoding="utf-8") as f:
            json.dump(meta, f)
        # An open drop box with no record of what went into it cannot answer
        # the one question that matters on the day somebody complains: what
        # was uploaded, when, and from where. The blobs expire; this line does
        # not, so "there is nothing in the box" and "nothing was ever put in
        # it" stay distinguishable. No filename guessing and no content -- just
        # enough to answer an abuse report and to notice a flood.
        try:
            with open(os.path.join(ROOT, "uploads.log"), "a",
                      encoding="utf-8") as lg:
                lg.write("%s %s %s %d %s %s\n" % (
                    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
                    fid, self._client(), got, meta["sha256"], meta["name"]))
        except OSError as e:
            sys.stderr.write("AGENTDROP-LOG-FAILED %r\n" % (e,))
        when = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(meta["keep_until"]))
        kept = ("expires %s (deleted then, as asked)" % when if hard else
                "kept-until %s at least, and every download extends it to %g "
                "days from that download" % (when, ttl / 24))
        return self._say(201,
                         "%s/%s\n"
                         "sha256 %s\n"
                         "size %d bytes\n"
                         "%s\n"
                         "delete-token %s\n"
                         % (BASE, fid, meta["sha256"], got, kept, meta["token"]))

    def do_DELETE(self):
        p = self._parts()
        if p and p[0] == "f":
            p = p[1:]
        if not p or not _ID.match(p[0]):
            return self._say(400, "DELETE %s/<id> with X-Delete-Token\n" % BASE)
        m = self._meta(p[0])
        if not m:
            return self._say(404, "no such file (wrong id, or it was already removed)\n")
        tok = self.headers.get("X-Delete-Token") or ""
        # Constant time: the token is the only thing standing between a reader
        # and deleting somebody else's file.
        if not secrets.compare_digest(tok, m.get("token", "")):
            return self._say(403, "wrong or missing X-Delete-Token\n")
        _remove(m, "DELETED")
        _log_removed(m, "DELETED", time.time())
        return self._say(200, "deleted\n")


def main():
    os.makedirs(ROOT, exist_ok=True)
    os.chmod(ROOT, 0o700)
    n = _sweep()
    # 2026-09-03: I fired the quota with AGENTDROP_ROOT set -- the variable is
    # AGENTDROP_DIR -- so the "test" instance ran against the LIVE store. What
    # is worth recording is that this line already said so: the log I redirected
    # it to began `store=/var/lib/agentdrop`, and I never opened the file. My
    # first instinct was to add a second banner; the banner was not missing.
    # Same shape as merging a red CI build -- the check ran, the verdict was
    # printed, and nobody read it. Caps and per-file limits are printed too now,
    # so one line answers "what is this instance actually enforcing".
    sys.stderr.write("agentdrop on 127.0.0.1:%d store=%s swept=%d free=%s"
                     " cap=%d per-file=%d floor=%d\n"
                     % (PORT, ROOT, n, shutil.disk_usage(ROOT).free,
                        STORE_CAP, MAX_BYTES, DISK_FLOOR))
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
