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

const format = (v, n) => (v === 4 ? formatV4(n) : formatV6(n));

/**
 * Parse an IP rule → { v, lo, hi } (inclusive) or null. Accepted forms: a
 * single address, CIDR ("10.0.0.0/8", "2001:db8::/32") or an inclusive range
 * of two addresses of the same family ("10.0.0.5-10.0.0.20", spaces allowed).
 */
export function parseRule(s) {
  if (typeof s !== 'string' || s.length > 100) return null;
  const parts = s.split('-');
  if (parts.length === 2) {
    const a = parseIp(parts[0]);
    const b = parseIp(parts[1]);
    if (!a || !b || a.v !== b.v || a.n > b.n) return null;
    return { v: a.v, lo: a.n, hi: b.n };
  }
  if (parts.length !== 1) return null;
  const c = parseCidr(s);
  if (!c) return null;
  const size = 1n << BigInt(bits(c.v) - c.prefix);
  return { v: c.v, lo: c.n, hi: c.n + size - 1n };
}

/** True when the parsed rule covers the parsed address. */
export function ruleContains(rule, ip) {
  return !!rule && !!ip && rule.v === ip.v && ip.n >= rule.lo && ip.n <= rule.hi;
}

/**
 * Normalize a rule string to its canonical form, or null if invalid: CIDR
 * ("a/len") when the rule is exactly one aligned block, else "lo-hi".
 */
export function normalizeRule(s) {
  const r = parseRule(s);
  if (!r) return null;
  const count = r.hi - r.lo + 1n;
  // Exactly a power of two, aligned on its size → a CIDR block.
  if ((count & (count - 1n)) === 0n && r.lo % count === 0n) {
    const prefix = bits(r.v) - (count.toString(2).length - 1);
    return `${format(r.v, r.lo)}/${prefix}`;
  }
  return `${format(r.v, r.lo)}-${format(r.v, r.hi)}`;
}
