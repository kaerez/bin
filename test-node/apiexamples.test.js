// apiexamples.test.js — the Account page's "Using the API" examples and
// docs/API.md say the same thing: every use case of an API key, in curl,
// Node.js and Python, with the server filled in and never a key. (The e2e
// suite runs each example against a real server.)
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { API_EXAMPLES, API_LANGS, EXAMPLE_SERVER, apiExamples } from '../public/dashboard/js/apiexamples.js';
import { API_SCOPES } from '../src/lib/settings.js';

const docs = readFileSync(new URL('../docs/API.md', import.meta.url), 'utf8');

describe('API examples', () => {
  it('cover every use case in every language', () => {
    expect(API_EXAMPLES.map((e) => e.id)).toEqual(['create-note', 'create-files', 'list', 'receipts', 'label', 'extend', 'revoke', 'delete', 'policy']);
    expect(API_LANGS.map(([k]) => k)).toEqual(['curl', 'node', 'python']);
    for (const e of API_EXAMPLES) {
      expect(e.scope === null || API_SCOPES.includes(e.scope)).toBe(true);
      for (const [k] of API_LANGS) expect(e[k].join('\n')).toContain(EXAMPLE_SERVER);
    }
    // Every scope has an example.
    expect(new Set(API_EXAMPLES.map((e) => e.scope).filter(Boolean))).toEqual(new Set(API_SCOPES));
  });

  it('never contain a key or a token, only the environment variables', () => {
    for (const e of API_EXAMPLES) {
      for (const [k] of API_LANGS) {
        const t = e[k].join('\n');
        expect(t).not.toMatch(/sbk_[A-Za-z0-9_-]{8,}/);
        if (e.scope) expect(t).toContain('SECBIN_API_KEY');
        else expect(t).not.toContain('SECBIN_API_KEY');
      }
    }
  });

  it('are in docs/API.md word for word', () => {
    for (const e of API_EXAMPLES) {
      expect(docs).toContain(`### ${e.title}`);
      for (const [k] of API_LANGS) expect(docs).toContain(e[k].join('\n'));
    }
  });

  it('fill in the server', () => {
    const ex = apiExamples('http://127.0.0.1:8787');
    expect(ex.find((e) => e.id === 'list').code.curl).toContain('http://127.0.0.1:8787/api/private/shares?status=active');
    expect(JSON.stringify(ex)).not.toContain(EXAMPLE_SERVER);
  });

  it('the docs no longer say keys cannot list or change anything', () => {
    expect(docs).not.toMatch(/cannot (sign\s+in, )?list or change/);
    for (const s of API_SCOPES) expect(docs).toContain(`| \`${s}\` |`);
  });
});
