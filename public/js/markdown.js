// markdown.js — a deliberately small, safe Markdown subset for rendering
// decrypted pastes. In a zero-knowledge app an XSS is a key leak (SECURITY.md
// §4), so this renderer:
//   • parses to a node tree (pure `parse()` — testable without a DOM),
//   • NEVER interprets raw HTML — any HTML in the source becomes literal text,
//   • sanitizes link hrefs to an http/https/mailto allowlist,
//   • and mounts via document.createElement + textContent only (no innerHTML).
//
// `parse()` and `sanitizeUrl()` are exported for the adversarial test suite.

const SAFE_SCHEME = /^(https?:|mailto:)/;
// ASCII control chars + space (0x00–0x20). Browsers ignore these inside a URL
// scheme, which enables "java\tscript:" style bypasses — so strip them first.
// eslint-disable-next-line no-control-regex -- matching control chars is the point
const CTRL_WS = /[\u0000-\u0020]/g;

/** Return a safe href, or null if the URL is not on the scheme allowlist. */
export function sanitizeUrl(raw) {
  if (typeof raw !== 'string') return null;
  const cleaned = raw.replace(CTRL_WS, '').toLowerCase();
  if (SAFE_SCHEME.test(cleaned)) return raw.trim().replace(CTRL_WS, '');
  return null;
}

// ── inline parsing (code → links → emphasis) ─────────────────────────────────

function parseEmphasis(str) {
  const nodes = [];
  const re = /(\*\*|__)(.+?)\1|(\*|_)(.+?)\3/g;
  let m, last = 0;
  while ((m = re.exec(str))) {
    if (m.index > last) nodes.push({ type: 'text', value: str.slice(last, m.index) });
    if (m[1]) nodes.push({ type: 'strong', children: parseEmphasis(m[2]) });
    else nodes.push({ type: 'em', children: parseEmphasis(m[4]) });
    last = re.lastIndex;
  }
  if (last < str.length) nodes.push({ type: 'text', value: str.slice(last) });
  return nodes;
}

// A URL runs to the first ")" or white space (as `[^)\s]*` would).
const URL_STOP = /[)\s]/g;

/**
 * The links of `str`: exactly what the pattern /\[([^\]]*)\]\(([^)\s]*)\)/g
 * finds, scanned in linear time. That regex retried from every "[" to the end
 * of the paragraph, so 300 000 "[" (or "[](x" repeated) froze the tab for
 * seconds. Here each "[" looks for the first "]" after it, and each "](" for
 * the first ")" or white space after it; both are remembered while the scan
 * moves on (every "[" before that "]" has the same one, and fails or matches
 * the same way), so each character is read a bounded number of times.
 */
function parseLinks(str) {
  const nodes = [];
  let last = 0;
  let from = 0;
  let close = -1; // the first "]" after the current "[" (valid while it is after it)
  let stop = -1; // the first ")" or white space at or after the current URL's start
  for (;;) {
    const open = str.indexOf('[', from);
    if (open < 0) break;
    if (close <= open) { close = str.indexOf(']', open + 1); if (close < 0) break; }
    if (str[close + 1] === '(') {
      const u = close + 2;
      if (stop < u) {
        URL_STOP.lastIndex = u;
        const s = URL_STOP.exec(str);
        stop = s ? s.index : str.length;
      }
      if (str[stop] === ')') {
        if (open > last) nodes.push(...parseEmphasis(str.slice(last, open)));
        const href = sanitizeUrl(str.slice(u, stop));
        const children = parseEmphasis(str.slice(open + 1, close));
        // Unsafe/absent URL → drop the link, keep its text. Never emit a bad href.
        if (href) nodes.push({ type: 'link', href, children });
        else nodes.push(...children);
        last = from = stop + 1;
        continue;
      }
    }
    // No link starts at any "[" before this "]": go on after it.
    from = close + 1;
  }
  if (last < str.length) nodes.push(...parseEmphasis(str.slice(last)));
  return nodes;
}

function parseInline(str) {
  const nodes = [];
  const re = /`([^`]+)`/g;
  let m, last = 0;
  while ((m = re.exec(str))) {
    if (m.index > last) nodes.push(...parseLinks(str.slice(last, m.index)));
    nodes.push({ type: 'code', value: m[1] });
    last = re.lastIndex;
  }
  if (last < str.length) nodes.push(...parseLinks(str.slice(last)));
  return nodes;
}

// ── block parsing ────────────────────────────────────────────────────────────

const RE_HEADING = /^(#{1,6})\s+(.*)$/;
const RE_HR = /^\s*([-*_])(?:\s*\1){2,}\s*$/;
const RE_ULI = /^\s*[-*+]\s+(.*)$/;
const RE_OLI = /^\s*\d+\.\s+(.*)$/;

// Render budget: a hostile paste up to the 1 MiB plaintext cap could parse into
// hundreds of thousands of blocks/inline nodes (one-char paragraphs, dense
// inline code) and freeze the tab when mounted. Above either budget the source
// is rendered verbatim as a single code block — the raw view, not a data loss.
export const MAX_MD_BYTES = 300_000;
export const MAX_MD_NODES = 30_000;

function countNodes(nodes) {
  let n = 0;
  for (const node of nodes) {
    n++;
    if (node.inline) n += countNodes(node.inline);
    if (node.children) n += countNodes(node.children);
    if (node.items) for (const item of node.items) n += 1 + countNodes(item);
  }
  return n;
}

/** Parse Markdown source into a safe block-node tree. Pure; no DOM. */
export function parse(md) {
  const src = typeof md === 'string' ? md : String(md ?? '');
  if (src.length > MAX_MD_BYTES) return [{ type: 'code_block', text: src }];
  const lines = src.replace(/\r\n?/g, '\n').split('\n');
  const blocks = [];
  let i = 0;

  const para = [];
  const flushPara = () => {
    if (para.length) blocks.push({ type: 'paragraph', inline: parseInline(para.join('\n')) });
    para.length = 0;
  };

  while (i < lines.length) {
    const line = lines[i];

    if (/^```/.test(line)) {
      flushPara();
      const body = [];
      i++;
      while (i < lines.length && !/^```/.test(lines[i])) body.push(lines[i++]);
      i++; // consume closing fence (if present)
      blocks.push({ type: 'code_block', text: body.join('\n') });
      continue;
    }

    if (line.trim() === '') { flushPara(); i++; continue; }

    if (RE_HR.test(line)) { flushPara(); blocks.push({ type: 'hr' }); i++; continue; }

    const h = RE_HEADING.exec(line);
    if (h) {
      flushPara();
      blocks.push({ type: 'heading', level: h[1].length, inline: parseInline(h[2]) });
      i++;
      continue;
    }

    if (line.startsWith('>')) {
      flushPara();
      const quote = [];
      while (i < lines.length && lines[i].startsWith('>')) quote.push(lines[i++].replace(/^>\s?/, ''));
      blocks.push({ type: 'blockquote', inline: parseInline(quote.join('\n')) });
      continue;
    }

    if (RE_ULI.test(line) || RE_OLI.test(line)) {
      flushPara();
      const ordered = RE_OLI.test(line);
      const items = [];
      while (i < lines.length) {
        const mm = ordered ? RE_OLI.exec(lines[i]) : RE_ULI.exec(lines[i]);
        if (!mm) break;
        items.push(parseInline(mm[1]));
        i++;
      }
      blocks.push({ type: 'list', ordered, items });
      continue;
    }

    para.push(line);
    i++;
  }
  flushPara();
  // Node budget (parsing is linear-fast; DOM mounting is what freezes) — bail
  // to the verbatim code-block fallback rather than mount an enormous tree.
  if (countNodes(blocks) > MAX_MD_NODES) return [{ type: 'code_block', text: src }];
  return blocks;
}

// ── DOM mounting (browser only; uses createElement + textContent) ────────────

function mountInline(parent, nodes) {
  for (const n of nodes) {
    if (n.type === 'text') {
      parent.appendChild(document.createTextNode(n.value));
    } else if (n.type === 'code') {
      const el = document.createElement('code');
      el.textContent = n.value;
      parent.appendChild(el);
    } else if (n.type === 'strong' || n.type === 'em') {
      const el = document.createElement(n.type === 'strong' ? 'strong' : 'em');
      mountInline(el, n.children);
      parent.appendChild(el);
    } else if (n.type === 'link') {
      const el = document.createElement('a');
      el.setAttribute('href', n.href);          // href already scheme-checked
      el.setAttribute('rel', 'noopener noreferrer nofollow ugc');
      el.setAttribute('target', '_blank');
      mountInline(el, n.children);
      // Said, not only done (WCAG 3.2.5): the link opens a new tab.
      const hint = document.createElement('span');
      hint.className = 'sr-only';
      hint.textContent = ' (opens in a new tab)';
      el.appendChild(hint);
      parent.appendChild(el);
    }
  }
}

/** Render Markdown into `container` (cleared first). Browser only. */
export function renderMarkdown(container, md) {
  container.textContent = '';
  for (const b of parse(md)) {
    if (b.type === 'heading') {
      const el = document.createElement('h' + b.level);
      mountInline(el, b.inline);
      container.appendChild(el);
    } else if (b.type === 'paragraph') {
      const el = document.createElement('p');
      mountInline(el, b.inline);
      container.appendChild(el);
    } else if (b.type === 'blockquote') {
      const el = document.createElement('blockquote');
      mountInline(el, b.inline);
      container.appendChild(el);
    } else if (b.type === 'code_block') {
      const pre = document.createElement('pre');
      const code = document.createElement('code');
      code.textContent = b.text;
      pre.appendChild(code);
      container.appendChild(pre);
    } else if (b.type === 'hr') {
      container.appendChild(document.createElement('hr'));
    } else if (b.type === 'list') {
      const list = document.createElement(b.ordered ? 'ol' : 'ul');
      for (const item of b.items) {
        const li = document.createElement('li');
        mountInline(li, item);
        list.appendChild(li);
      }
      container.appendChild(list);
    }
  }
}
