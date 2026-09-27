// apiexamples.js — the "Using the API" examples on the Account page, for
// every use case of an API key, in curl, Node.js (fetch) and Python
// (requests). docs/API.md shows the same text (test-node/apiexamples.test.js
// keeps the two in sync) and the e2e suite runs each one against a server.
// Written for EXAMPLE_SERVER; apiExamples() puts this server's origin in.

export const EXAMPLE_SERVER = 'https://bin.example.com';
export const API_LANGS = [['curl', 'curl'], ['node', 'Node.js'], ['python', 'Python']];

/** [{ id, title, scope (null: no API key), curl, node, python }] — code as lines. */
export const API_EXAMPLES = [
  {
    id: "create-note", title: "Create a note", scope: "notes",
    curl: [
      "# curl cannot encrypt: encrypt locally first (Node.js 22, from a clone of the repository).",
      "# It prints \"fragment: <F>\" on stderr; the link is https://bin.example.com/p/<id>#<F>",
      "echo \"the secret\" | node examples/api/create-note.mjs --encrypt-only --views 1 > note.json",
      "curl -sS -H \"Authorization: Bearer $SECBIN_API_KEY\" -H \"Content-Type: application/json\" \\",
      "  --data @note.json https://bin.example.com/api/private/paste",
    ],
    node: [
      "# From a clone of the repository (it uses the browser's own protocol module); reads SECBIN_API_KEY",
      "echo \"the secret\" | node examples/api/create-note.mjs https://bin.example.com --views 1 --expire 24h",
    ],
    python: [
      "# pip install requests cryptography argon2-cffi; reads SECBIN_API_KEY",
      "echo \"the secret\" | python3 examples/api/create_note.py https://bin.example.com --views 1 --expire 24h",
    ],
  },
  {
    id: "create-files", title: "Share files (the upload flow)", scope: "files",
    curl: [
      "# curl cannot encrypt: prepare the encrypted upload locally first (Node.js 22, from a clone).",
      "# It writes upload/init.json, upload/chunk-<i>.bin and upload/finalize.json and prints",
      "# \"fragment: <F>\" on stderr; the link is https://bin.example.com/p/<id>#<F>",
      "node examples/api/create-files.mjs --encrypt-only upload report.pdf --views 3 --expire 7d",
      "H=\"Authorization: Bearer $SECBIN_API_KEY\"",
      "init=$(curl -sS -H \"$H\" -H \"Content-Type: application/json\" --data @upload/init.json https://bin.example.com/api/private/file)",
      "id=$(echo \"$init\" | jq -r .id); tok=$(echo \"$init\" | jq -r .uploadtoken)",
      "echo \"delete token: $(echo \"$init\" | jq -r .deletetoken)\"",
      "for f in upload/chunk-*.bin; do i=${f##*-}; i=${i%.bin}",
      "  curl -sS -X PUT -H \"$H\" -H \"X-Upload-Token: $tok\" -H \"Content-Type: application/octet-stream\" \\",
      "    --data-binary @\"$f\" \"https://bin.example.com/api/private/file/$id/chunk/$i\"",
      "done",
      "curl -sS -H \"$H\" -H \"X-Upload-Token: $tok\" -H \"Content-Type: application/json\" \\",
      "  --data @upload/finalize.json \"https://bin.example.com/api/private/file/$id/finalize\"",
    ],
    node: [
      "# Files and folders, from a clone of the repository; reads SECBIN_API_KEY",
      "node examples/api/create-files.mjs https://bin.example.com report.pdf --views 3 --expire 7d",
    ],
    python: [
      "# pip install requests cryptography argon2-cffi (create_note.py must sit next to it); reads SECBIN_API_KEY",
      "python3 examples/api/create_files.py https://bin.example.com report.pdf --views 3 --expire 7d",
    ],
  },
  {
    id: "list", title: "List your shares", scope: "read",
    curl: [
      "curl -sS -H \"Authorization: Bearer $SECBIN_API_KEY\" \"https://bin.example.com/api/private/shares?status=active\"",
      "# one share (views left, expiry, opens):",
      "curl -sS -H \"Authorization: Bearer $SECBIN_API_KEY\" \"https://bin.example.com/api/private/shares/$SHARE_ID\"",
    ],
    node: [
      "// list-shares.mjs (run: node list-shares.mjs)",
      "const res = await fetch('https://bin.example.com/api/private/shares?status=active', {",
      "  headers: { authorization: `Bearer ${process.env.SECBIN_API_KEY}` },",
      "});",
      "if (!res.ok) throw new Error(`HTTP ${res.status}: ${(await res.json()).error}`);",
      "const { rows, total } = await res.json();",
      "for (const s of rows) console.log(s.id, s.kind, s.status, s.left ?? 'unlimited', s.opens, s.label);",
      "console.log(`${rows.length} of ${total}`);",
    ],
    python: [
      "# list_shares.py (run: python3 list_shares.py)",
      "import os, requests",
      "",
      "res = requests.get(\"https://bin.example.com/api/private/shares\", params={\"status\": \"active\"}, timeout=30,",
      "                   headers={\"Authorization\": f\"Bearer {os.environ['SECBIN_API_KEY']}\"})",
      "res.raise_for_status()",
      "data = res.json()",
      "for s in data[\"rows\"]:",
      "    print(s[\"id\"], s[\"kind\"], s[\"status\"], s[\"left\"], s[\"opens\"], s[\"label\"])",
      "print(len(data[\"rows\"]), \"of\", data[\"total\"])",
    ],
  },
  {
    id: "receipts", title: "Read receipts (who opened a share, when)", scope: "read",
    curl: [
      "curl -sS -H \"Authorization: Bearer $SECBIN_API_KEY\" \"https://bin.example.com/api/private/shares/$SHARE_ID/opens\"",
    ],
    node: [
      "// receipts.mjs (run: SHARE_ID=... node receipts.mjs)",
      "const res = await fetch(`https://bin.example.com/api/private/shares/${process.env.SHARE_ID}/opens`, {",
      "  headers: { authorization: `Bearer ${process.env.SECBIN_API_KEY}` },",
      "});",
      "if (!res.ok) throw new Error(`HTTP ${res.status}: ${(await res.json()).error}`);",
      "const { total, fields, rows } = await res.json();",
      "console.log(`${total} opens; details: ${fields.join(', ') || 'times only'}`);",
      "for (const r of rows) console.log(new Date(r.ts * 1000).toISOString(), r.country ?? '', r.browser ?? '');",
    ],
    python: [
      "# receipts.py (run: SHARE_ID=... python3 receipts.py)",
      "import os, time, requests",
      "",
      "res = requests.get(f\"https://bin.example.com/api/private/shares/{os.environ['SHARE_ID']}/opens\", timeout=30,",
      "                   headers={\"Authorization\": f\"Bearer {os.environ['SECBIN_API_KEY']}\"})",
      "res.raise_for_status()",
      "data = res.json()",
      "print(data[\"total\"], \"opens; details:\", \", \".join(data[\"fields\"]) or \"times only\")",
      "for r in data[\"rows\"]:",
      "    print(time.strftime(\"%Y-%m-%dT%H:%M:%SZ\", time.gmtime(r[\"ts\"])), r.get(\"country\", \"\"), r.get(\"browser\", \"\"))",
    ],
  },
  {
    id: "label", title: "Label a share", scope: "manage",
    curl: [
      "# the label is NOT encrypted: the server and its administrators can read it",
      "curl -sS -X PATCH -H \"Authorization: Bearer $SECBIN_API_KEY\" -H \"Content-Type: application/json\" \\",
      "  --data '{\"label\":\"quarterly report\"}' \"https://bin.example.com/api/private/shares/$SHARE_ID\"",
    ],
    node: [
      "// label.mjs (run: SHARE_ID=... node label.mjs) — the label is NOT encrypted",
      "const res = await fetch(`https://bin.example.com/api/private/shares/${process.env.SHARE_ID}`, {",
      "  method: 'PATCH',",
      "  headers: { authorization: `Bearer ${process.env.SECBIN_API_KEY}`, 'content-type': 'application/json' },",
      "  body: JSON.stringify({ label: 'quarterly report' }),",
      "});",
      "console.log(res.status, await res.json());",
    ],
    python: [
      "# label.py (run: SHARE_ID=... python3 label.py) — the label is NOT encrypted",
      "import os, requests",
      "",
      "res = requests.patch(f\"https://bin.example.com/api/private/shares/{os.environ['SHARE_ID']}\", timeout=30,",
      "                     json={\"label\": \"quarterly report\"},",
      "                     headers={\"Authorization\": f\"Bearer {os.environ['SECBIN_API_KEY']}\"})",
      "print(res.status_code, res.json())",
    ],
  },
  {
    id: "extend", title: "Extend a share (more views, later expiry)", scope: "manage",
    curl: [
      "# views and expiry only grow; views only for view-limited shares; expires is in unix seconds",
      "curl -sS -X PATCH -H \"Authorization: Bearer $SECBIN_API_KEY\" -H \"Content-Type: application/json\" \\",
      "  --data \"{\\\"views\\\":5,\\\"expires\\\":$(( $(date +%s) + 7 * 86400 ))}\" \"https://bin.example.com/api/private/shares/$SHARE_ID\"",
    ],
    node: [
      "// extend.mjs (run: SHARE_ID=... node extend.mjs) — views and expiry only grow",
      "const expires = Math.floor(Date.now() / 1000) + 7 * 86400; // unix seconds",
      "const res = await fetch(`https://bin.example.com/api/private/shares/${process.env.SHARE_ID}`, {",
      "  method: 'PATCH',",
      "  headers: { authorization: `Bearer ${process.env.SECBIN_API_KEY}`, 'content-type': 'application/json' },",
      "  body: JSON.stringify({ views: 5, expires }),",
      "});",
      "console.log(res.status, await res.json());",
    ],
    python: [
      "# extend.py (run: SHARE_ID=... python3 extend.py) — views and expiry only grow",
      "import os, time, requests",
      "",
      "res = requests.patch(f\"https://bin.example.com/api/private/shares/{os.environ['SHARE_ID']}\", timeout=30,",
      "                     json={\"views\": 5, \"expires\": int(time.time()) + 7 * 86400},  # unix seconds",
      "                     headers={\"Authorization\": f\"Bearer {os.environ['SECBIN_API_KEY']}\"})",
      "print(res.status_code, res.json())",
    ],
  },
  {
    id: "revoke", title: "Revoke a share", scope: "manage",
    curl: [
      "# the content is destroyed at once; the share stays in your list as \"revoked\"",
      "curl -sS -X POST -H \"Authorization: Bearer $SECBIN_API_KEY\" -H \"X-Secbin-Intent: 1\" \\",
      "  \"https://bin.example.com/api/private/shares/$SHARE_ID/revoke\"",
    ],
    node: [
      "// revoke.mjs (run: SHARE_ID=... node revoke.mjs)",
      "const res = await fetch(`https://bin.example.com/api/private/shares/${process.env.SHARE_ID}/revoke`, {",
      "  method: 'POST',",
      "  headers: { authorization: `Bearer ${process.env.SECBIN_API_KEY}`, 'x-secbin-intent': '1' },",
      "});",
      "console.log(res.status, await res.json());",
    ],
    python: [
      "# revoke.py (run: SHARE_ID=... python3 revoke.py)",
      "import os, requests",
      "",
      "res = requests.post(f\"https://bin.example.com/api/private/shares/{os.environ['SHARE_ID']}/revoke\", timeout=30,",
      "                    headers={\"Authorization\": f\"Bearer {os.environ['SECBIN_API_KEY']}\", \"X-Secbin-Intent\": \"1\"})",
      "print(res.status_code, res.json())",
    ],
  },
  {
    id: "delete", title: "Delete with the delete token (no API key)", scope: null,
    curl: [
      "# the delete token is the capability; notes are /api/paste/<id>, file shares /api/file/<id>",
      "curl -sS -X DELETE -H \"X-Delete-Token: $SECBIN_DELETE_TOKEN\" \"https://bin.example.com/api/paste/$SHARE_ID\"",
    ],
    node: [
      "// delete.mjs (run: SHARE_ID=... SECBIN_DELETE_TOKEN=... node delete.mjs)",
      "const id = process.env.SHARE_ID;",
      "const kind = id.startsWith('f') ? 'file' : 'paste'; // file shares' ids start with \"f\"",
      "const res = await fetch(`https://bin.example.com/api/${kind}/${id}`, {",
      "  method: 'DELETE',",
      "  headers: { 'x-delete-token': process.env.SECBIN_DELETE_TOKEN },",
      "});",
      "console.log(res.status, await res.json());",
    ],
    python: [
      "# delete.py (run: SHARE_ID=... SECBIN_DELETE_TOKEN=... python3 delete.py)",
      "import os, requests",
      "",
      "sid = os.environ[\"SHARE_ID\"]",
      "kind = \"file\" if sid.startswith(\"f\") else \"paste\"  # file shares' ids start with \"f\"",
      "res = requests.delete(f\"https://bin.example.com/api/{kind}/{sid}\", timeout=30,",
      "                      headers={\"X-Delete-Token\": os.environ[\"SECBIN_DELETE_TOKEN\"]})",
      "print(res.status_code, res.json())",
    ],
  },
  {
    id: "policy", title: "Read your policy (what to check before creating)", scope: "policy",
    curl: [
      "curl -sS -H \"Authorization: Bearer $SECBIN_API_KEY\" https://bin.example.com/api/private/policy",
    ],
    node: [
      "// policy.mjs (run: node policy.mjs)",
      "const res = await fetch('https://bin.example.com/api/private/policy', {",
      "  headers: { authorization: `Bearer ${process.env.SECBIN_API_KEY}` },",
      "});",
      "console.log(res.status, await res.json()); // { url, urlRules }",
    ],
    python: [
      "# policy.py (run: python3 policy.py)",
      "import os, requests",
      "",
      "res = requests.get(\"https://bin.example.com/api/private/policy\", timeout=30,",
      "                   headers={\"Authorization\": f\"Bearer {os.environ['SECBIN_API_KEY']}\"})",
      "print(res.status_code, res.json())  # {\"url\": ..., \"urlRules\": [...]}",
    ],
  },
];

/** The examples with `origin` as the server: [{ id, title, scope, code: { curl, node, python } }]. */
export function apiExamples(origin) {
  const at = (lines) => lines.join('\n').replaceAll(EXAMPLE_SERVER, origin);
  return API_EXAMPLES.map((e) => ({ id: e.id, title: e.title, scope: e.scope, code: Object.fromEntries(API_LANGS.map(([k]) => [k, at(e[k])])) }));
}
