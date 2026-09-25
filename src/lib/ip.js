// ip.js — IPv4/IPv6 parsing, CIDR matching and tracking-key aggregation for
// the brute-force guard and manual allow/block rules. Pure; BigInt arithmetic.

const V4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

function parseV4(s) {
  if (!V4_RE.test(s)) return null;
  return s.split('.').reduce((acc, o) => (acc << 8n) | BigInt(Number(o)), 0n);
}

function parseV6(s) {
  if (typeof s !== 'string' || s.length > 45 || !/^[0-9a-fA-F:.]+$/.test(s)) return null;
  let tail = [];
  const lastColon = s.lastIndexOf(':');
  if (s.includes('.')) {
    // Embedded IPv4 (e.g. ::ffff:1.2.3.4)
    const v4 = parseV4(s.slice(lastColon + 1));
    if (v4 === null) return null;
    tail = [Number((v4 >> 16n) & 0xffffn), Number(v4 & 0xffffn)];
    s = s.slice(0, lastColon + 1) + '0:0';
  }
  const dbl = s.split('::');
  if (dbl.length > 2) return null;
  const head = dbl[0] ? dbl[0].split(':') : [];
  const rest = dbl.length === 2 && dbl[1] ? dbl[1].split(':') : [];
  let groups;
  if (dbl.length === 2) {
    const fill = 8 - head.length - rest.length;
    if (fill < 1) return null;
    groups = [...head, ...Array(fill).fill('0'), ...rest];
  } else {
    groups = head;
  }
  if (groups.length !== 8) return null;
  let v = 0n;
  for (const g of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    v = (v << 16n) | BigInt(parseInt(g, 16));
  }
  if (tail.length) v = (v & ~0xffffffffn) | (BigInt(tail[0]) << 16n) | BigInt(tail[1]);
  return v;
}

/** Parse an address → { v: 4|6, n: BigInt } or null. IPv4-mapped IPv6 → v4. */
export function parseIp(s) {
  if (typeof s !== 'string') return null;
  s = s.trim();
  const v4 = parseV4(s);
  if (v4 !== null) return { v: 4, n: v4 };
  const v6 = parseV6(s);
  if (v6 === null) return null;
  if (v6 >> 32n === 0xffffn) return { v: 4, n: v6 & 0xffffffffn };
  return { v: 6, n: v6 };
}

const bits = (v) => (v === 4 ? 32 : 128);

/** Parse "addr" or "addr/prefix" → { v, n, prefix } (network bits masked) or null. */
export function parseCidr(s) {
  if (typeof s !== 'string') return null;
  const [addr, pfx, extra] = s.trim().split('/');
  if (extra !== undefined) return null;
  const ip = parseIp(addr);
  if (!ip) return null;
  let prefix = bits(ip.v);
  if (pfx !== undefined) {
    if (!/^\d{1,3}$/.test(pfx)) return null;
    prefix = Number(pfx);
    // An IPv4-mapped v6 range narrows to its IPv4 part.
    if (ip.v === 4 && addr.includes(':')) prefix -= 96;
    if (prefix < 0 || prefix > bits(ip.v)) return null;
  }
  const mask = prefix === 0 ? 0n : ((1n << BigInt(prefix)) - 1n) << BigInt(bits(ip.v) - prefix);
  return { v: ip.v, n: ip.n & mask, prefix };
}

export function cidrContains(cidr, ip) {
  if (!cidr || !ip || cidr.v !== ip.v) return false;
  const shift = BigInt(bits(ip.v) - cidr.prefix);
  return cidr.prefix === 0 || (ip.n >> shift) === (cidr.n >> shift);
}

function formatV4(n) {
  return [24n, 16n, 8n, 0n].map((s) => Number((n >> s) & 0xffn)).join('.');
}

function formatV6(n) {
  const g = [];
  for (let i = 7; i >= 0; i--) g.push(Number((n >> BigInt(i * 16)) & 0xffffn).toString(16));
  return g.join(':');
}

export function formatCidr(c) {
  return `${c.v === 4 ? formatV4(c.n) : formatV6(c.n)}/${c.prefix}`;
}

/**
 * Tracking key for an address: IPv4 as a /32, IPv6 aggregated to `v6Prefix`
 * (default /64 — a single customer allocation), so rotating within one prefix
 * does not dodge the guard. Unparseable input maps to a stable "invalid" key.
 */
export function trackingKey(addr, v6Prefix = 64) {
  const ip = parseIp(addr);
  if (!ip) return 'invalid';
  if (ip.v === 4) return `${formatV4(ip.n)}/32`;
  const p = Math.min(128, Math.max(16, v6Prefix | 0));
  return formatCidr(parseCidr(`${formatV6(ip.n)}/${p}`));
}

/** Normalize a rule string to canonical CIDR form, or null if invalid. */
export function normalizeRule(s) {
  const c = parseCidr(s);
  return c ? formatCidr(c) : null;
}
