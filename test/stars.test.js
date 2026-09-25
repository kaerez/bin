// stars.test.js — the /api/stars proxy behind the topbar GitHub badge.
//
// GitHub itself is mocked (fetchMock): the suite must not depend on the network
// or on the live star count. What matters is that a good payload becomes a
// cacheable number and that every anomaly fails closed as a 502 rather than
// inventing one.
import { SELF } from 'cloudflare:test';
import { describe, it, expect, afterEach, vi } from 'vitest';
import { parseStars } from '../src/lib/stars.js';

const ORIGIN = 'https://binthere.test';
const REPO_API = 'https://api.github.com/repos/nxfu/binthere';

// The suite runs inside the Worker, so stubbing the global reaches the
// subrequest fetchStars makes.
const realFetch = globalThis.fetch;
function mockRepo(status, body) {
  const calls = [];
  globalThis.fetch = (input, init) => {
    calls.push(new Request(input, init));
    return Promise.resolve(new Response(typeof body === 'string' ? body : JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/json' },
    }));
  };
  return calls;
}

afterEach(() => {
  globalThis.fetch = realFetch;
  vi.restoreAllMocks();
});

describe('GET /api/stars', () => {
  it('answers with the count and lets it be cached', async () => {
    const calls = mockRepo(200, { stargazers_count: 49, full_name: 'nxfu/binthere' });

    const res = await SELF.fetch(`${ORIGIN}/api/stars`);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ stars: 49 });
    // Every other route is no-store; this one is public and visitor-independent.
    expect(res.headers.get('cache-control')).toMatch(/^public, max-age=\d+$/);

    expect(calls.length).toBe(1);
    expect(calls[0].url).toBe(REPO_API);
    // GitHub rejects API requests that don't identify themselves.
    expect(calls[0].headers.get('user-agent')).toBeTruthy();
  });

  it('is a 502 when GitHub errors, and is not cached for long', async () => {
    mockRepo(500, 'upstream is unhappy');

    const res = await SELF.fetch(`${ORIGIN}/api/stars`);
    expect(res.status).toBe(502);
    expect(res.headers.get('cache-control')).toBe('public, max-age=60');
  });

  it('is a 502 when the request to GitHub fails outright', async () => {
    globalThis.fetch = () => Promise.reject(new Error('network down'));

    const res = await SELF.fetch(`${ORIGIN}/api/stars`);
    expect(res.status).toBe(502);
  });

  it('is a 502 when the payload has no usable count', async () => {
    mockRepo(200, { stargazers_count: 'many' });

    const res = await SELF.fetch(`${ORIGIN}/api/stars`);
    expect(res.status).toBe(502);
  });

  it('rejects non-GET methods with an Allow header', async () => {
    const res = await SELF.fetch(`${ORIGIN}/api/stars`, { method: 'POST' });
    expect(res.status).toBe(405);
    expect(res.headers.get('allow')).toBe('GET');
  });
});

describe('parseStars', () => {
  it('accepts a repo payload', () => {
    expect(parseStars({ stargazers_count: 0 })).toBe(0);
    expect(parseStars({ stargazers_count: 1234 })).toBe(1234);
  });

  it('rejects anything that is not a non-negative integer count', () => {
    for (const bad of [
      null, undefined, 'nope', 42, [], [{ stargazers_count: 5 }],
      {}, { stargazers_count: null }, { stargazers_count: '5' },
      { stargazers_count: -1 }, { stargazers_count: 1.5 }, { stargazers_count: NaN },
    ]) {
      expect(parseStars(bad)).toBeNull();
    }
  });
});
