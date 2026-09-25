#!/usr/bin/env python3
"""create_note.py — create an end-to-end encrypted secbin note over plain REST.

Standalone reference client for the v2 note format (SPEC.md §2–§5): the note
is encrypted here, before anything is sent; the server only ever sees
ciphertext. The printed link carries the key in its #fragment — anyone with
the link (and the password, if you set one) can open the note.

    pip install cryptography argon2-cffi      # argon2-cffi only for --password
    export SECBIN_API_KEY=sbk_...             # an API key with the "notes" scope
    echo "the secret" | python3 create_note.py https://bin.example.com --views 1 --expire 24h

Never put the API key or a password on the command line; this script reads
the key from SECBIN_API_KEY and the password from SECBIN_NOTE_PASSWORD.
"""
import argparse
import base64
import hashlib
import json
import os
import sys
import unicodedata
import urllib.error
import urllib.request

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ARGON2_T, ARGON2_M_KIB, ARGON2_P = 3, 65536, 1   # SPEC.md §1


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def hkdf(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    # An empty salt means an all-zero salt (RFC 5869), as Web Crypto does.
    return HKDF(algorithm=SHA256(), length=32, salt=salt or None, info=info).derive(ikm)


def build_aad(adata: dict) -> bytes:
    """Canonical AAD (SPEC.md §4): order and newlines are load-bearing."""
    lines = ["secbin/v2", f"alg={adata['alg']}", f"kdf={adata['kdf']}", f"iter={adata['iter']}",
             f"comp={adata['comp']}", f"fmt={adata['fmt']}", f"bar={'1' if adata['bar'] else '0'}",
             f"ivc={adata['ivc']}", f"ivw={adata['ivw']}", f"skdf={adata['skdf']}"]
    return ("\n".join(lines) + "\n").encode("utf-8")


def encrypt_note(text: str, password: str = "", views=None, expire: str = "24h", fmt: str = "plaintext"):
    """→ (create body, fragment). Mirrors encryptPaste() in public/js/crypto.js (no compression)."""
    data = text.encode("utf-8")
    if len(data) > 1 << 20:
        raise SystemExit("note too large (max 1 MiB)")
    cek, f, ivc, ivw = os.urandom(32), os.urandom(32), os.urandom(12), os.urandom(12)
    use_pw = len(password) > 0
    salt = os.urandom(16) if use_pw else b""
    bar = views is not None
    adata = {"alg": "A256GCM", "kdf": "argon2id-hkdf" if use_pw else "hkdf", "iter": ARGON2_T if use_pw else 0,
             "comp": "none", "fmt": fmt, "bar": bar, "ivc": b64url(ivc), "ivw": b64url(ivw),
             "skdf": b64url(salt) if use_pw else ""}
    aad = build_aad(adata)
    pw_ikm = b""
    if use_pw:
        from argon2.low_level import Type, hash_secret_raw
        pw_ikm = hash_secret_raw(unicodedata.normalize("NFC", password).encode("utf-8"), salt,
                                 time_cost=ARGON2_T, memory_cost=ARGON2_M_KIB, parallelism=ARGON2_P,
                                 hash_len=32, type=Type.ID)
    kek = hkdf(f, pw_ikm, b"secbin/v2 kek")
    link_proof = hkdf(f, b"", b"secbin/v2 link-proof")
    key_proof = hkdf(kek, b"", b"secbin/v2 key-proof")
    wk = AESGCM(kek).encrypt(ivw, cek, aad)
    ct = AESGCM(cek).encrypt(ivc, data, aad)
    meta = {"expire": expire}
    if bar:
        meta["views"] = views
    body = {"v": 2, "ct": b64url(ct), "wk": b64url(wk), "adata": adata, "meta": meta,
            "acc": {"lh": b64url(hashlib.sha256(link_proof).digest()), "kh": b64url(hashlib.sha256(key_proof).digest())}}
    return body, b64url(f)


def main() -> int:
    ap = argparse.ArgumentParser(description="Create an encrypted secbin note from stdin.")
    ap.add_argument("server", help="e.g. https://bin.example.com")
    ap.add_argument("--views", type=int, default=None, help="view limit (1–100000); default unlimited")
    ap.add_argument("--expire", default="24h", help="e.g. 10m, 24h, 7d (default 24h)")
    ap.add_argument("--label", default="", help="your own label (NOT encrypted — visible to the server)")
    args = ap.parse_args()
    key = os.environ.get("SECBIN_API_KEY", "")
    if not key.startswith("sbk_"):
        print("set SECBIN_API_KEY to an API key (sbk_...)", file=sys.stderr)
        return 2
    text = sys.stdin.read()
    if not text:
        print("nothing on stdin", file=sys.stderr)
        return 2
    body, fragment = encrypt_note(text, os.environ.get("SECBIN_NOTE_PASSWORD", ""), args.views, args.expire)
    server = args.server.rstrip("/")
    req = urllib.request.Request(f"{server}/api/private/paste", method="POST",
                                 data=json.dumps({"paste": body, "label": args.label}).encode(),
                                 headers={"authorization": f"Bearer {key}", "content-type": "application/json",
                                          "user-agent": "secbin-example-python/1"})
    try:
        with urllib.request.urlopen(req, timeout=30) as res:
            out = json.load(res)
    except urllib.error.HTTPError as e:
        try:
            err = json.load(e)
        except Exception:
            err = {"message": e.reason}
        print(f"error {e.code}: {err.get('message') or err.get('error')}", file=sys.stderr)
        return 1
    print(f"{server}/p/{out['id']}#{fragment}")
    print(f"delete token: {out['deletetoken']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
