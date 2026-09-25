// stars.js — the GitHub star count behind the topbar badge.
//
// The page cannot call api.github.com itself (CSP: connect-src 'self'), so the
// Worker proxies it and answers `{"stars":N}`. The upstream call is edge-cached,
// so a burst of visitors costs GitHub one request per colo per TTL instead of
// one per page load — well inside the 60/hour unauthenticated limit. Nothing
// here touches paste data; it is a public, visitor-independent number.

const REPO_API = 'https://api.github.com/repos/nxfu/binthere';

/** How long a count may be stale, at the edge and in the browser. */
export const STARS_TTL = 1800;
/** Shorter, so a GitHub outage isn't pinned for half an hour. */
export const STARS_ERROR_TTL = 60;

/**
 * Fetch the repository's star count. Returns null on any anomaly — a failed
 * request, a non-200, or a payload that isn't a repo object — so the caller can
 * answer honestly rather than serve a made-up number.
 */
export async function fetchStars() {
  let res;
  try {
    res = await fetch(REPO_API, {
      headers: {
        // GitHub rejects API requests without a User-Agent and asks that it
        // identify the caller.
        'user-agent': 'binthere (+https://binthere.gaury.dev)',
        accept: 'application/vnd.github+json',
      },
      // Ignored by `wrangler dev` (no edge cache locally), so dev hits GitHub
      // on every load.
      cf: { cacheTtlByStatus: { '200-299': STARS_TTL, '400-599': STARS_ERROR_TTL } },
    });
  } catch {
    return null;
  }
  if (!res.ok) return null;

  let data;
  try {
    data = await res.json();
  } catch {
    return null;
  }
  return parseStars(data);
}

/** Pull the count out of a GitHub repo payload; null if it isn't one. */
export function parseStars(data) {
  if (data === null || typeof data !== 'object' || Array.isArray(data)) return null;
  const n = data.stargazers_count;
  return Number.isInteger(n) && n >= 0 ? n : null;
}
