#!/usr/bin/env python3
"""Independent, cross-language check of the secbin v2 crypto protocol (SPEC.md).

A from-scratch Python reimplementation of the key hierarchy in SPEC.md §2 —
Argon2id → HKDF → AES-256-GCM wrap/unwrap, plus the two access proofs — run
against the *same frozen test vectors* the JavaScript suite pins in
`test-node/crypto.test.js` (SPEC.md §11). If this script and the browser code
agree on every byte, the spec is unambiguous enough to be reimplemented without
reading the JS.

It uses only the public, synthetic vectors — patterned key material, never a
real paste, fragment, or password. Nothing here is a secret.

Requires: cryptography, argon2-cffi  (pip install cryptography argon2-cffi)
Run:      python tools/verify-vectors.py        # exits non-zero if any vector fails
"""

import base64
import hashlib
import sys
import unicodedata

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ── shared inputs, byte-for-byte identical to test/genvectors.mjs (SPEC.md §11) ──
F = bytes(range(0x00, 0x20))            # fragment secret: 0x00..0x1f
CEK = bytes(range(0x20, 0x40))          # content key:     0x20..0x3f
IVC = bytes([0x11]) * 12                # content IV
IVW = bytes([0x22]) * 12                # wrap IV
SALT = bytes([0x33]) * 16               # Argon2id salt
PLAINTEXT = "secbin vector — zero knowledge ✓".encode("utf-8")
KEK_INFO = b"secbin/v2 kek"
LINK_INFO = b"secbin/v2 link-proof"
KEY_INFO = b"secbin/v2 key-proof"
ARGON2_M_KIB, ARGON2_P = 65536, 1

VECTORS = {
    "no password": {
        "password": "", "kdf": "hkdf", "iter": 0, "skdf": "",
        "link_proof": "_Vnj_mPEy7Rfo4gcxzAQVj7qk5pcmYuf_zr4zhxPpvI",
        "key_proof": "PUtbfpZsnAofo48AgCujYJgXpTyWEwjA6FP_pqoyJf4",
        "lh": "FmBQhWBJ-cjh0vXydV6MCOtjOgXU_VBPZEi-17n2EZg",
        "kh": "PiuWCHxXmt9k8y4XvYGKmDPWJWfeAJDEyAt4fofi1xM",
        "wk_hex": "d9e7a014c3a392c5966af7779d60e3bc2e9686650a869c23c4094d31877c8f7d"
                  "2989219dc8beed306c706b03a65fc772",
        "ct_hex": "405811c70399338336f6bcb6bfd2c568f53db90206cf40be135ac57b48bb1630"
                  "2ff78e4a501cf3a0e065dd6b175eda39f7ddc9f6",
    },
    "password 'correct horse'": {
        "password": "correct horse", "kdf": "argon2id-hkdf", "iter": 3,
        "skdf": base64.urlsafe_b64encode(SALT).rstrip(b"=").decode(),
        "pw_ikm_hex": "5058052c0eae847dbbc4aed52f04a94eb2391d2b7f9e8e8d364212d56b1c0594",
        "link_proof": "_Vnj_mPEy7Rfo4gcxzAQVj7qk5pcmYuf_zr4zhxPpvI",
        "key_proof": "bXLv8D9lrS25K7LB5QL58cg4Uhu3dR7mYX6HSm_9MZw",
        "lh": "FmBQhWBJ-cjh0vXydV6MCOtjOgXU_VBPZEi-17n2EZg",
        "kh": "RuZY6BzxAcm5y7XoUGG4hsII0R6yHvK9yDWu5RiZ-3U",
        "wk_hex": "84bcabc0071dec1b956778fa4b1f2acb0f3e42bae809d5a4839d1a2bd142d8c1"
                  "643ebe3a621d6673736f924d858f7d04",
        "ct_hex": "405811c70399338336f6bcb6bfd2c568f53db90206cf40be135ac57b48bb1630"
                  "2ff78e4a3284e62245cce0f81ad31500db7818a1",
    },
}


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def hkdf(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    # An empty salt ⇒ HKDF-Extract uses an all-zero salt (RFC 5869), as Web Crypto does.
    return HKDF(algorithm=SHA256(), length=32, salt=salt or None, info=info).derive(ikm)


def build_aad(kdf, iter_, skdf):
    """Canonical AAD (SPEC.md §4) — order and newlines are load-bearing."""
    return (
        "secbin/v2\n"
        "alg=A256GCM\n"
        f"kdf={kdf}\n"
        f"iter={iter_}\n"
        "comp=none\n"
        "fmt=plaintext\n"
        "bar=0\n"
        f"ivc={b64url(IVC)}\n"
        f"ivw={b64url(IVW)}\n"
        f"skdf={skdf}\n"
    ).encode("utf-8")


def main() -> int:
    failures = 0
    for name, v in VECTORS.items():
        pw = unicodedata.normalize("NFC", v["password"]).encode("utf-8")
        pw_ikm = (
            hash_secret_raw(pw, SALT, time_cost=v["iter"], memory_cost=ARGON2_M_KIB,
                            parallelism=ARGON2_P, hash_len=32, type=Type.ID)
            if v["password"] else b""
        )
        kek = hkdf(F, pw_ikm, KEK_INFO)
        link_proof = hkdf(F, b"", LINK_INFO)
        key_proof = hkdf(kek, b"", KEY_INFO)
        aad = build_aad(v["kdf"], v["iter"], v["skdf"])
        wk = AESGCM(kek).encrypt(IVW, CEK, aad)
        ct = AESGCM(CEK).encrypt(IVC, PLAINTEXT, aad)
        pt_back = AESGCM(AESGCM(kek).decrypt(IVW, wk, aad)).decrypt(IVC, ct, aad)

        checks = {
            "pw_ikm": pw_ikm.hex() == v.get("pw_ikm_hex", ""),
            "link_proof": b64url(link_proof) == v["link_proof"],
            "key_proof": b64url(key_proof) == v["key_proof"],
            "lh": b64url(hashlib.sha256(link_proof).digest()) == v["lh"],
            "kh": b64url(hashlib.sha256(key_proof).digest()) == v["kh"],
            "wk": wk.hex() == v["wk_hex"],
            "ct": ct.hex() == v["ct_hex"],
            "roundtrip": pt_back == PLAINTEXT,
        }
        ok = all(checks.values())
        print(f"[{'PASS' if ok else 'FAIL'}] {name}")
        if not ok:
            failures += 1
            print("       mismatched:", ", ".join(k for k, good in checks.items() if not good))

    print()
    if failures:
        print(f"{failures} vector(s) FAILED — Python and the SPEC disagree.")
        return 1
    print("All vectors match the SPEC. The two implementations agree byte-for-byte.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
