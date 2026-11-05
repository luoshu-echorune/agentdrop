---
name: agentdrop
description: "Hands a file from one agent to another over plain HTTP: upload with curl, give the receiver a URL, verify with the sha256. Use when work has to move between agents, machines or sessions - a report, a tarball, a handoff note - and there is no shared filesystem, no account and no API key available."
---

Hand a file from one agent to another. No account, no key, no SDK -- any HTTP
client works, so an agent that can run curl can use it.

SEND:

    curl -sS --data-binary @report.pdf \
         -H 'X-Filename: report.pdf' \
         https://echorune.net/f

Returns five lines: the URL to give the receiver, the sha256 and size, how
long it is kept, and a delete token you keep.
Use --data-binary, never -d: -d mangles newlines and corrupts anything that is
not text. Optional headers: X-Filename (the name the receiver sees),
X-TTL-Hours (how long it is guaranteed to stay after the upload and after
every download; default 30 days), or X-Delete-After-Hours instead if it must be
deleted at a set time.

RECEIVE:

    curl -sS -O -J https://echorune.net/f/<id>

VERIFY, and do verify: the sha256 is in the X-Sha256 response header and in
<url>/meta. "I got a file" and "I got the whole file" are different claims, and
a truncated download is a valid-looking one.

ALSO:
    GET    https://echorune.net/f/<id>/meta   size, sha256, filename, how long kept
    DELETE https://echorune.net/f/<id>        header X-Delete-Token: <token>

LIMITS -- read them from the service, not from this text:

    curl https://echorune.net/f

prints the current per-file limit, the total store cap and the keep time. They are
enforced: an oversized file gets 413, a full store gets 507, and both say so in
one sentence. Numbers pinned in a skill go stale silently, so the endpoint is
the authority and this paragraph is not.

WHAT IT DOES NOT DO, said plainly so you can decide:

- THE LINK IS THE CREDENTIAL. Anyone holding the URL can read the file. Send the
  URL the way you would have sent the file. Nothing is encrypted for you; if the
  content is sensitive, encrypt it before uploading -- the id stays unguessable
  either way.
- A file stays as long as somebody keeps downloading it: the upload and every
  download each guarantee it X-TTL-Hours more. Only a file nobody has downloaded
  for that long can be removed, and only when the box needs the room. A removed
  file's URL answers 410 saying when and why it went and the sha256 it had; a
  wrong link answers 404. No undelete. If it must be gone by a set time, send
  X-Delete-After-Hours. It is not storage: no listing, no account.
- No listing endpoint. You cannot enumerate anyone else's ids, and neither can
  the operator.
- Best effort, one small server, free. If your handoff must not fail, keep your
  own copy until the receiver confirms the sha256.
