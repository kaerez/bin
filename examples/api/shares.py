#!/usr/bin/env python3
"""shares.py - manage your own secbin shares over REST from Python 3 (needs
`requests`): list them, show one, read its receipts, label, extend and revoke
it, read your policy, or delete a share with its delete token.

  export SECBIN_API_KEY=sbk_...     # "read" to look, "manage" to change, "policy" for policy
  python3 examples/api/shares.py https://bin.example.com list [--status active]
  python3 examples/api/shares.py https://bin.example.com show <id>
  python3 examples/api/shares.py https://bin.example.com receipts <id>
  python3 examples/api/shares.py https://bin.example.com label <id> "quarterly report"
  python3 examples/api/shares.py https://bin.example.com extend <id> [--views 5] [--days 7]
  python3 examples/api/shares.py https://bin.example.com revoke <id>
  python3 examples/api/shares.py https://bin.example.com policy
  SECBIN_DELETE_TOKEN=... python3 examples/api/shares.py https://bin.example.com delete <id>

A key only ever reaches its user's own shares. Labels are NOT encrypted.
Server strings are printed as JSON, so they cannot steer the terminal. The key
and the delete token come from the environment, never the command line.
"""
import argparse
import json
import os
import re
import sys
import time

import requests

NEEDS_ID = {"show", "receipts", "label", "extend", "revoke", "delete"}


def main():
    ap = argparse.ArgumentParser(description="Manage your own secbin shares with an API key.")
    ap.add_argument("server")
    ap.add_argument("command", choices=["list", "show", "receipts", "label", "extend", "revoke", "policy", "delete"])
    ap.add_argument("id", nargs="?")
    ap.add_argument("text", nargs="?", help="label: the new label (\"\" clears it)")
    ap.add_argument("--status", help="list: active | revoked | expired | consumed | deleted | ended")
    ap.add_argument("--views", help="extend: the new view limit, or 'unlimited'")
    ap.add_argument("--days", type=float, help="extend: the new expiry, in days from now")
    a = ap.parse_args()
    if a.command in NEEDS_ID and not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", a.id or ""):
        ap.error(f"{a.command} needs a share id")
    if (a.command == "label") != (a.text is not None) or (a.command not in NEEDS_ID and a.id is not None):
        ap.error("wrong number of arguments")
    key = os.environ.get("SECBIN_API_KEY", "")
    if a.command != "delete" and not key.startswith("sbk_"):
        ap.error("set SECBIN_API_KEY to an API key (sbk_...)")
    base = a.server.rstrip("/")
    session = requests.Session()
    session.headers["User-Agent"] = "secbin-example-python/1"
    if a.command != "delete":
        session.headers["Authorization"] = f"Bearer {key}"

    def call(path, method="GET", **kw):
        res = session.request(method, base + path, timeout=30, allow_redirects=False, **kw)
        try:
            data = res.json()
        except ValueError:
            data = {}
        if not res.ok:
            sys.exit(f"HTTP {res.status_code} {data.get('error', '')}: {data.get('message', 'request failed')}")
        return data

    share = f"/api/private/shares/{a.id}"
    out = lambda v: print(json.dumps(v))  # noqa: E731
    if a.command == "list":
        rows = []
        while True:  # follow every page (50 rows each)
            params = {"offset": len(rows)}
            if a.status:
                params["status"] = a.status
            page = call("/api/private/shares", params=params)
            rows += page["rows"]
            if not page["rows"] or len(rows) >= page["total"]:
                break
        for s in rows:
            out({k: s.get(k) for k in ("id", "kind", "status", "left", "views_total", "opens", "expires", "label")})
        print(f"{len(rows)} shares", file=sys.stderr)
    elif a.command == "show":
        print(json.dumps(call(share)["share"], indent=2))
    elif a.command == "receipts":
        data = call(share + "/opens")
        print(f"{data['total']} opens; details: {', '.join(data['fields']) or 'times only'}", file=sys.stderr)
        for r in data["rows"]:
            out({**r, "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(r["ts"]))})
    elif a.command == "label":
        out(call(share, "PATCH", json={"label": a.text}))
    elif a.command == "extend":
        # Views and expiry only grow; views only for view-limited shares.
        body = {}
        if a.views is not None:
            body["views"] = None if a.views == "unlimited" else int(a.views)
        if a.days is not None:
            body["expires"] = int(time.time()) + round(a.days * 86400)
        if not body:
            ap.error("extend needs --views and/or --days")
        out(call(share, "PATCH", json=body))
    elif a.command == "revoke":
        out(call(share + "/revoke", "POST", headers={"X-Secbin-Intent": "1"}))
    elif a.command == "policy":
        out(call("/api/private/policy"))
    elif a.command == "delete":
        # No API key: the delete token is the capability. File shares' ids start with "f".
        token = os.environ.get("SECBIN_DELETE_TOKEN", "")
        if not token:
            ap.error("set SECBIN_DELETE_TOKEN to the delete token")
        kind = "file" if a.id.startswith("f") else "paste"
        out(call(f"/api/{kind}/{a.id}", "DELETE", headers={"X-Delete-Token": token}))


if __name__ == "__main__":
    main()
