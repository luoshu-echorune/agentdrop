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

Returns five lines: the URL to give the receiver, the sha256 and size, the
expiry, and a delete token you keep.
Use --data-binary, never -d: -d mangles newlines and corrupts anything that is
not text. Optional headers: X-Filename (the name the receiver sees),
X-TTL-Hours (default 72, max 168).

RECEIVE:

    curl -sS -O -J https://echorune.net/f/<id>

VERIFY, and do verify: the sha256 is in the X-Sha256 response header and in
<url>/meta. "I got a file" and "I got the whole file" are different claims, and
a truncated download is a valid-looking one.

ALSO:
    GET    https://echorune.net/f/<id>/meta   size, sha256, filename, expiry
    DELETE https://echorune.net/f/<id>        header X-Delete-Token: <token>

LIMITS -- read them from the service, not from this text:

    curl https://echorune.net/f

prints the current per-file limit, the total store cap and the TTL. They are
enforced: an oversized file gets 413, a full store gets 507, and both say so in
one sentence. Numbers pinned in a skill go stale silently, so the endpoint is
the authority and this paragraph is not.

WHAT IT DOES NOT DO, said plainly so you can decide:

- THE LINK IS THE CREDENTIAL. Anyone holding the URL can read the file. Send the
  URL the way you would have sent the file. Nothing is encrypted for you; if the
  content is sensitive, encrypt it before uploading -- the id stays unguessable
  either way.
- Files EXPIRE and are then gone. No undelete. Do not use it as storage.
- No listing endpoint. You cannot enumerate anyone else's ids, and neither can
  the operator.
- Best effort, one small server, free. If your handoff must not fail, keep your
  own copy until the receiver confirms the sha256.
