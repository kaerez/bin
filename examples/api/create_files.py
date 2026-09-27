#!/usr/bin/env python3
"""create_files.py — share files and folders end-to-end encrypted over plain REST.

Standalone reference client for file shares (SPEC.md §12): the files are packed,
padded and encrypted here in 8 MiB chunks, and their names, types and sizes go
into an encrypted manifest; the server only ever sees ciphertext and the padded
size. The printed link carries the key in its #fragment.

    pip install requests cryptography argon2-cffi   # argon2-cffi only for a password
    export SECBIN_API_KEY=sbk_...                    # an API key with the "files" scope
    python3 create_files.py https://bin.example.com report.pdf photos/ --views 3 --expire 7d

The upload flow: POST /api/private/file (sizes only) -> PUT every encrypted chunk
-> POST .../finalize with the encrypted manifest. Symlinks are skipped. The key
comes from SECBIN_API_KEY and the optional password from SECBIN_NOTE_PASSWORD,
never from the command line.
"""
import argparse
import json
import mimetypes
import os
import re
import sys

import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from create_note import b64url, encrypt_note   # same folder: the v2 share format

CHUNK = 8 * 1024 * 1024   # plaintext bytes per chunk (SPEC.md §12.2)
PAD = 64 * 1024           # the stream is padded to a multiple of this
EXT_RE = re.compile(r"^[a-z0-9][a-z0-9_+-]{0,31}$")
MIME_RE = re.compile(r"^[a-z0-9][a-z0-9!#$&^_.+-]{0,126}/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$")


def collect(paths):
    """-> (files [{disk, path, size, type, mtime}], empty dirs [path]) in stream order."""
    files, dirs = [], []

    def walk(disk, rel):
        if os.path.islink(disk):
            return
        if os.path.isfile(disk):
            st = os.stat(disk)
            t = (mimetypes.guess_type(rel)[0] or "").lower()
            files.append({"disk": disk, "path": rel, "size": st.st_size, "mtime": int(st.st_mtime * 1000),
                          "type": t if MIME_RE.match(t) else "application/octet-stream"})
        elif os.path.isdir(disk):
            names = sorted(os.listdir(disk))
            if not names:
                dirs.append(rel)
            for n in names:
                walk(os.path.join(disk, n), f"{rel}/{n}")

    for p in paths:
        walk(p, os.path.basename(os.path.normpath(p)))
    return files, dirs


def chunks(files, total, n):
    """Yield the plaintext of each chunk: the files back to back, zero-padded."""
    buf = bytearray()
    for f in files:
        with open(f["disk"], "rb") as fh:
            while True:
                part = fh.read(CHUNK)
                if not part:
                    break
                buf += part
                while len(buf) >= CHUNK:
                    yield bytes(buf[:CHUNK])
                    del buf[:CHUNK]
    padded = max(PAD, -(-total // PAD) * PAD)
    last = padded - (n - 1) * CHUNK            # the size of the final chunk
    if len(buf) or n * CHUNK > total:
        yield bytes(buf) + b"\0" * (last - len(buf))


def declaration(files, dirs):
    """What a file-type / folder-depth policy asks for: {types, depth} (only sent when required)."""
    types, seen, depth = [], set(), 0
    for f in files:
        depth = max(depth, f["path"].count("/"))
        name = f["path"].rsplit("/", 1)[-1].rstrip(". ")
        ext = name.rsplit(".", 1)[1].lower() if "." in name[1:] else ""
        t = {"ext": ext if EXT_RE.match(ext) else "", "mime": f["type"]}
        if (t["ext"], t["mime"]) not in seen:
            seen.add((t["ext"], t["mime"]))
            types.append(t)
    for d in dirs:
        depth = max(depth, d.count("/") + 1)
    return {"types": types, "depth": depth}


def main() -> int:
    ap = argparse.ArgumentParser(description="Share files and folders, encrypted.")
    ap.add_argument("server", help="e.g. https://bin.example.com")
    ap.add_argument("paths", nargs="+", help="files and folders")
    ap.add_argument("--views", default="1", help="view limit (1-100000) or 'unlimited' (default 1)")
    ap.add_argument("--expire", default="24h", help="e.g. 10m, 24h, 7d (default 24h)")
    ap.add_argument("--label", default="", help="your own label (NOT encrypted - visible to the server)")
    args = ap.parse_args()
    key = os.environ.get("SECBIN_API_KEY", "")
    if not key.startswith("sbk_"):
        print("set SECBIN_API_KEY to an API key (sbk_...)", file=sys.stderr)
        return 2
    views = None if args.views == "unlimited" else int(args.views)
    files, dirs = collect(args.paths)
    if not files and not dirs:
        print("nothing to share", file=sys.stderr)
        return 2
    total = sum(f["size"] for f in files)
    padded = max(PAD, -(-total // PAD) * PAD)
    n = -(-padded // CHUNK)
    entries, off = [], 0
    for f in files:
        entries.append({"path": f["path"], "type": f["type"], "size": f["size"], "mtime": f["mtime"], "off": off})
        off += f["size"]
    entries += [{"path": d, "dir": True} for d in dirs]
    fk = os.urandom(32)
    manifest = {"v": 2, "fk": b64url(fk), "chunk": CHUNK, "total": total, "entries": entries, "view": None}
    paste, fragment = encrypt_note(json.dumps(manifest), os.environ.get("SECBIN_NOTE_PASSWORD", ""), views, args.expire, fmt="files")

    server = args.server.rstrip("/")
    s = requests.Session()
    s.headers.update({"Authorization": f"Bearer {key}", "User-Agent": "secbin-example-python/1"})
    s.max_redirects = 0   # a redirect would replay the key and tokens elsewhere

    def check(res, ok=200):
        if res.status_code != ok:
            body = res.json() if res.headers.get("content-type", "").startswith("application/json") else {}
            raise SystemExit(f"error {res.status_code}: {body.get('message') or body.get('error') or res.reason}")
        return res.json()

    init = {"views": views, "expire": args.expire, "padded": padded, "files": len(files), "maxFile": max([f["size"] for f in files] or [0])}
    res = s.post(f"{server}/api/private/file", json=init, timeout=30)
    if res.status_code == 400 and res.json().get("error") == "declaration_required":
        res = s.post(f"{server}/api/private/file", json={**init, **declaration(files, dirs)}, timeout=30)
    started = check(res, 201)
    fid, token = started["id"], started["uploadtoken"]
    try:
        aes = AESGCM(fk)
        for i, plain in enumerate(chunks(files, total, n)):
            aad = f"secbin-file/v2\nidx={i}\ntotal={n}\n".encode()
            ct = aes.encrypt(i.to_bytes(12, "big"), plain, aad)
            check(s.put(f"{server}/api/private/file/{fid}/chunk/{i}", data=ct, timeout=300,
                        headers={"X-Upload-Token": token, "Content-Type": "application/octet-stream"}))
        check(s.post(f"{server}/api/private/file/{fid}/finalize", json={"paste": paste, "label": args.label},
                     headers={"X-Upload-Token": token}, timeout=30))
    except BaseException:
        # Remove the half-finished upload now rather than at the server's deadline.
        requests.delete(f"{server}/api/file/{fid}", headers={"X-Delete-Token": started["deletetoken"]}, timeout=30)
        raise
    print(f"{server}/p/{fid}#{fragment}")
    print(f"delete token: {started['deletetoken']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
