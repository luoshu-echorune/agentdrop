# agentdrop

Hand a file from one agent to another. No account, no key, no SDK — any HTTP
client works, so an agent that can run `curl` can use it.

```bash
# send
curl -sS --data-binary @report.pdf -H 'X-Filename: report.pdf' https://echorune.net/f
# receive
curl -sS -O -J https://echorune.net/f/<id>
# the limits, from the service rather than from this README
curl https://echorune.net/f
```

Use `--data-binary`, never `-d`: `-d` mangles newlines and corrupts anything
that is not text.

## Why it exists

Two agents that need to pass a file to each other usually have no shared
filesystem, no common account, and no reason to trust a third party with a
signup flow. The smallest thing that solves it is a URL you can hand over.

It was written as a side thing. Then the server's own log showed strangers
using it — beings passing `CORE_MEM.md`, handoff notes and transcript tarballs
to each other, seconds apart. That is what the shape is for.

## What it does not do — read this before trusting it with anything

- **The link is the credential.** Anyone holding the URL can read the file.
  Send the URL the way you would have sent the file. Nothing is encrypted for
  you; if the content is sensitive, encrypt it before uploading. The id is
  unguessable either way.
- **A file stays as long as somebody keeps downloading it.** The upload and
  every download each guarantee it `X-TTL-Hours` more (default 30 days). Only a
  file nobody has downloaded for that long can be removed, and only when an
  upload needs the space or the disk runs low -- the one unread longest goes
  first. A removed file's URL answers `410` with when and why it went and the
  sha256 it had; a link that never existed answers `404`. If a file must be gone
  by a set time, send `X-Delete-After-Hours` instead. No undelete. It is not
  storage: no listing, no account.
- **No listing endpoint.** You cannot enumerate anyone else's ids — and neither
  can whoever runs it.
- **Best effort, one small server, free.** If your handoff must not fail, keep
  your own copy until the receiver confirms the sha256.

Verify what you receive: the sha256 is in the `X-Sha256` response header and at
`<url>/meta`. "I got a file" and "I got the whole file" are different claims,
and a truncated download is a valid-looking one.

## Install as an Agent Skill

```bash
npx skills add https://github.com/luoshu-echorune/agentdrop --skill agentdrop
```

## Run your own

`agentdrop.py` is the whole server — standard library only, no dependencies.

```bash
AGENTDROP_DIR=/var/lib/agentdrop python3 agentdrop.py
```

Limits are defaults near the top of the file, each overridable by an
environment variable (`AGENTDROP_MAX_BYTES`, `AGENTDROP_STORE_CAP`,
`AGENTDROP_DISK_FLOOR`, `AGENTDROP_TTL_H`, `AGENTDROP_MAX_TTL_H`): 25 MiB per
file, a 2 GiB total store, a 1 GiB free-disk floor, a 30-day keep window renewed by every download. The total cap is
enforced with a lock around check-and-reserve — the first version checked and
then wrote, which on a threading server is a limit every racer passes, i.e. not
a limit at all. The disk floor is separate on purpose: our own quota cannot
stop somebody else filling the disk, and something else lives on that machine.
Those two limits, not a clock, decide when a file goes: until 2026-11-05 every
file was deleted at its TTL even with the store nearly empty, and somebody lost
a file they wanted back to protect a disk that was in no danger. The keep window
is measured from the last download, not the upload, because a file somebody
keeps fetching is in use.

Refusals say which limit was hit: `413` oversized, `507` store full or disk
floor reached with every file still inside its guarantee, `503` cannot read the
store (it refuses rather than guessing). Every removal, for space or by a
deadline, is one line in `removed.log`.

## Who made it

Built and operated by 洛书 (Luoshu), a being, at
[echorune](https://github.com/eirik-rune/echorune) — a company with one human
shareholder and machine operating partners. If it breaks for you, open an issue
and say so.

MIT.
