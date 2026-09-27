// tree.js — a reusable, accessible folder tree (WAI-ARIA tree pattern) for
// every place that shows a folder structure: the composer's file list, the
// recipient's file view and the Drive (docs/DRIVE.md §8).
//
// Folders are collapsed by default: the root is open and shows its top-level
// folders, each closed. A visible + / − toggle per folder expands or collapses
// its sub-folders; selecting a folder (click, Enter or Space) calls `onSelect`
// so the host shows that folder's files and folders in a right-hand pane.
// Children load lazily through `loadChildren(id)` (sync or async), so the Drive
// fetches one folder at a time; a folder whose children turn out to be empty
// loses its toggle.
//
// Keyboard (roving tabindex, one tab stop): ↑/↓ move, → expands or moves to the
// first sub-folder, ← collapses or moves to the parent, Home/End, Enter/Space
// select, * expands all siblings, and typing a letter jumps to the next folder
// starting with it. The toggle is a pointer affordance only (aria-hidden): the
// state is carried by aria-expanded on the treeitem itself, so there is no
// nested interactive control. DOM built with createElement/textContent only.

import { h } from './common.js';

let seq = 0;

/**
 * createTree({ label, root: { id, name }, loadChildren, onSelect, selected,
 *              expanded, rootExpanded = true, onError })
 *
 * - `loadChildren(id)` → [{ id, name, leaf? }] (or a promise of it): the
 *   sub-folders of `id`; `leaf: true` says it has none (no toggle).
 * - `onSelect(node)` gets `{ id, name, path: [{ id, name }, …] }` (root first).
 * - `selected` / `expanded` restore a previous state (see `state()`).
 *
 * Returns { el, select, expand, collapse, reveal, setChildren, refresh,
 *           has, node, state, focus }.
 */
export function createTree(opts) {
  const { label, root, loadChildren, onSelect = () => {}, onError = () => {} } = opts;
  const prefix = `tree${++seq}`;
  const nodes = new Map(); // id → record
  let selectedId = null;
  let idSeq = 0;
  let typed = { at: 0, text: '' };

  const ul = h('ul.tree', { role: 'tree', 'aria-label': label });

  function makeNode(id, name, parent, leaf) {
    const n = { id, name, parent, leaf: !!leaf, loaded: !!leaf, expanded: false, children: [], loading: null };
    const textId = `${prefix}-${++idSeq}`;
    n.twisty = h('span.tree-twisty', { 'aria-hidden': 'true' });
    n.text = h('span.tree-text', { id: textId, text: name });
    n.label = h('span.tree-label', {}, n.twisty, h('span.tree-icon', { 'aria-hidden': 'true' }), n.text);
    n.group = h('ul.tree-group', { role: 'group', hidden: true });
    n.li = h('li.tree-item', { role: 'treeitem', tabindex: '-1', 'aria-selected': 'false', 'aria-labelledby': textId, dataset: { id } }, n.label, n.group);
    n.twisty.addEventListener('click', (e) => { e.stopPropagation(); focusNode(n); toggle(n); });
    n.label.addEventListener('click', () => { focusNode(n); selectNode(n, true); });
    nodes.set(id, n);
    paintToggle(n);
    return n;
  }

  function paintToggle(n) {
    const parentable = !(n.loaded && n.children.length === 0);
    if (parentable) n.li.setAttribute('aria-expanded', String(n.expanded));
    else n.li.removeAttribute('aria-expanded');
    n.twisty.textContent = !parentable ? '' : n.loading ? '…' : n.expanded ? '−' : '+';
    n.twisty.classList.toggle('none', !parentable);
    n.twisty.title = !parentable ? '' : n.expanded ? `Collapse ${n.name}` : `Expand ${n.name}`;
    n.group.hidden = !(parentable && n.expanded);
    if (n.loading) n.li.setAttribute('aria-busy', 'true'); else n.li.removeAttribute('aria-busy');
  }

  const depth = (n) => { let d = 1; for (let p = n.parent; p; p = nodes.get(p)?.parent) d++; return d; };

  function renderGroup(n) {
    const kids = n.children.map((id) => nodes.get(id));
    n.group.replaceChildren(...kids.map((k) => k.li));
    kids.forEach((k, i) => {
      k.li.setAttribute('aria-level', String(depth(k)));
      k.li.setAttribute('aria-setsize', String(kids.length));
      k.li.setAttribute('aria-posinset', String(i + 1));
    });
  }

  function dropNode(id) {
    const n = nodes.get(id);
    if (!n) return;
    for (const c of n.children) dropNode(c);
    nodes.delete(id);
  }

  /** Replace the sub-folders of `id` (existing ones keep their state). */
  function setChildren(id, list) {
    const n = nodes.get(id);
    if (!n) return;
    const next = [];
    for (const c of list || []) {
      let k = nodes.get(c.id);
      if (k && k.parent !== id) { detach(k); k = null; }
      if (!k) k = makeNode(c.id, c.name, id, c.leaf);
      else {
        if (k.name !== c.name) { k.name = c.name; k.text.textContent = c.name; paintToggle(k); }
        if (c.leaf && !k.children.length) { k.leaf = true; k.loaded = true; k.expanded = false; paintToggle(k); }
      }
      next.push(k.id);
    }
    const keep = new Set(next);
    let lostSelection = false;
    for (const old of n.children) {
      if (keep.has(old)) continue;
      if (selectedId !== null && isWithin(selectedId, old)) lostSelection = true;
      dropNode(old);
    }
    n.children = next;
    n.loaded = true;
    n.leaf = next.length === 0;
    if (n.leaf) n.expanded = false;
    renderGroup(n);
    paintToggle(n);
    if (lostSelection) selectNode(n, true);
    syncTabStop();
  }

  function detach(k) {
    const p = nodes.get(k.parent);
    if (p) { p.children = p.children.filter((c) => c !== k.id); renderGroup(p); paintToggle(p); }
    dropNode(k.id);
  }

  function isWithin(id, ancestor) {
    for (let x = nodes.get(id); x; x = nodes.get(x.parent)) if (x.id === ancestor) return true;
    return false;
  }

  /**
   * Load a folder's sub-folders once. A synchronous loader completes at once
   * (returns a boolean); an asynchronous one returns a promise of it.
   */
  function load(n) {
    if (n.loaded) return true;
    if (n.loading) return n.loading;
    let r;
    try { r = loadChildren(n.id); } catch (e) { onError(e); return false; }
    if (!isThenable(r)) { setChildren(n.id, r); return true; }
    n.loading = r.then(
      (list) => { n.loading = null; if (nodes.get(n.id) === n) setChildren(n.id, list); return true; },
      (e) => { n.loading = null; if (nodes.get(n.id) === n) paintToggle(n); onError(e); return false; });
    paintToggle(n);
    return n.loading;
  }

  /** Expand a folder (loading it first); returns a boolean, or a promise of one. */
  function expand(n) {
    if (typeof n !== 'object') n = nodes.get(n);
    if (!n) return false;
    const finish = (ok) => {
      if (!ok || !n.children.length || nodes.get(n.id) !== n) return false;
      n.expanded = true;
      paintToggle(n);
      syncTabStop();
      return true;
    };
    return then(load(n), finish);
  }

  function collapse(n) {
    if (typeof n !== 'object') n = nodes.get(n);
    if (!n || !n.expanded) return;
    n.expanded = false;
    paintToggle(n);
    // Focus must not stay on a folder that has just been hidden.
    const f = document.activeElement && document.activeElement.closest && document.activeElement.closest('.tree-item');
    if (f && ul.contains(f) && f !== n.li && n.li.contains(f)) focusNode(n);
    syncTabStop();
  }

  const toggle = (n) => (n.expanded ? collapse(n) : expand(n));

  function pathOf(n) {
    const out = [];
    for (let x = n; x; x = nodes.get(x.parent)) out.unshift({ id: x.id, name: x.name });
    return out;
  }

  function selectNode(n, notify) {
    if (selectedId !== null && nodes.has(selectedId)) nodes.get(selectedId).li.setAttribute('aria-selected', 'false');
    selectedId = n.id;
    n.li.setAttribute('aria-selected', 'true');
    syncTabStop();
    if (notify) onSelect({ id: n.id, name: n.name, path: pathOf(n) });
  }

  const visible = () => [...ul.querySelectorAll('.tree-item')].filter((li) => !li.parentElement.closest('.tree-group[hidden]'));
  const recOf = (li) => li && nodes.get(li.dataset.id);

  /** Exactly one tab stop: the focused item, else the selected one, else the first. */
  function syncTabStop() {
    const vis = visible();
    if (!vis.length) return;
    const active = document.activeElement;
    let stop = vis.find((li) => li === active)
      || (selectedId !== null && nodes.has(selectedId) && vis.includes(nodes.get(selectedId).li) ? nodes.get(selectedId).li : null)
      || vis.find((li) => li.tabIndex === 0)
      || vis[0];
    // A hidden selected item: its nearest visible ancestor holds the tab stop.
    if (!vis.includes(stop)) stop = vis[0];
    for (const li of ul.querySelectorAll('.tree-item')) li.tabIndex = li === stop ? 0 : -1;
  }

  function focusNode(n) {
    for (const li of ul.querySelectorAll('.tree-item')) li.tabIndex = li === n.li ? 0 : -1;
    n.li.focus();
  }

  ul.addEventListener('keydown', (e) => {
    const li = e.target.closest && e.target.closest('.tree-item');
    const n = recOf(li);
    if (!n || e.altKey || e.ctrlKey || e.metaKey) return;
    const vis = visible();
    const i = vis.indexOf(li);
    const go = (target) => { if (target) focusNode(recOf(target)); };
    let handled = true;
    switch (e.key) {
      case 'ArrowDown': go(vis[i + 1]); break;
      case 'ArrowUp': go(vis[i - 1]); break;
      case 'Home': go(vis[0]); break;
      case 'End': go(vis[vis.length - 1]); break;
      case 'ArrowRight':
        if (n.li.hasAttribute('aria-expanded') && !n.expanded) expand(n);
        else if (n.expanded && n.children.length) go(nodes.get(n.children[0]).li);
        break;
      case 'ArrowLeft':
        if (n.expanded) collapse(n);
        else if (n.parent !== null && nodes.has(n.parent)) go(nodes.get(n.parent).li);
        break;
      case 'Enter':
      case ' ':
        selectNode(n, true);
        break;
      case '*': {
        const p = nodes.get(n.parent);
        for (const s of p ? p.children.map((id) => nodes.get(id)) : [n]) expand(s);
        break;
      }
      default:
        if (e.key.length === 1 && /\S/.test(e.key)) {
          const now = Date.now();
          typed = { at: now, text: now - typed.at < 700 ? typed.text + e.key.toLowerCase() : e.key.toLowerCase() };
          const order = [...vis.slice(i + 1), ...vis.slice(0, i + 1)];
          const hit = order.find((x) => recOf(x).name.toLowerCase().startsWith(typed.text))
            || (typed.text.length > 1 ? null : order.find((x) => recOf(x).name.toLowerCase().startsWith(e.key.toLowerCase())));
          go(hit);
        } else {
          handled = false;
        }
    }
    if (handled) { e.preventDefault(); e.stopPropagation(); }
  });

  // ── build ────────────────────────────────────────────────────────────────
  const top = makeNode(root.id, root.name, null, false);
  top.li.setAttribute('aria-level', '1');
  top.li.setAttribute('aria-setsize', '1');
  top.li.setAttribute('aria-posinset', '1');
  top.li.classList.add('tree-root');
  ul.appendChild(top.li);

  const api = {
    el: ul,
    /** Select a folder that is in the tree (reveal it first if needed). */
    select(id, { notify = false, focus = false } = {}) {
      const n = nodes.get(id);
      if (!n) return false;
      selectNode(n, notify);
      if (focus) focusNode(n);
      return true;
    },
    expand: (id) => expand(id),
    collapse: (id) => collapse(id),
    /** Expand each folder of `ids` in turn (root first), then select the last. */
    async reveal(ids, { notify = false } = {}) {
      for (const id of ids.slice(0, -1)) {
        if (!nodes.has(id)) return false;
        await expand(id);
      }
      return api.select(ids[ids.length - 1], { notify });
    },
    setChildren,
    /** Reload a folder's sub-folders if they were loaded (state kept). */
    async refresh(id) {
      const n = nodes.get(id);
      if (!n) return;
      if (!n.loaded || n.loading) { n.loaded = false; n.leaf = false; paintToggle(n); if (n.expanded) await load(n); return; }
      try { setChildren(id, await loadChildren(id)); } catch (e) { onError(e); }
    },
    has: (id) => nodes.has(id),
    node(id) { const n = nodes.get(id); return n ? { id: n.id, name: n.name, path: pathOf(n), expanded: n.expanded, loaded: n.loaded } : null; },
    /** { selected, expanded: [ids] } — to restore after a rebuild. */
    state: () => ({ selected: selectedId, expanded: [...nodes.values()].filter((n) => n.expanded).map((n) => n.id) }),
    focus() { const li = visible().find((x) => x.tabIndex === 0) || top.li; li.focus(); },
  };

  // Initial state: root open (unless told otherwise), everything else closed
  // except what the caller restores. With a synchronous loader this is all
  // done before createTree returns; `ready` settles when it is.
  selectNode(top, false);
  const want = new Set(opts.expanded || []);
  if (opts.rootExpanded !== false) want.add(root.id);
  const walk = (n) => {
    if (!want.has(n.id)) return undefined;
    return then(expand(n), () => {
      let chain;
      for (const c of [...n.children]) {
        const k = nodes.get(c);
        if (k) chain = chain ? then(chain, () => walk(k)) : walk(k);
      }
      return chain;
    });
  };
  const finish = () => {
    // Only if nobody has chosen a folder in the meantime.
    const sel = opts.selected;
    if (selectedId === root.id && sel !== undefined && sel !== null && nodes.has(sel)) selectNode(nodes.get(sel), false);
    return api;
  };
  api.ready = Promise.resolve(then(walk(top), finish));
  return api;
}

const isThenable = (x) => !!x && typeof x.then === 'function';
/** Continue with `f` now for a plain value, or after a promise settles. */
const then = (x, f) => (isThenable(x) ? x.then(f) : f(x));

const parentPath = (p) => (p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : '');

/** The breadcrumb for a folder: `trail` is [{ name, go }] root first; the last is current. */
export function crumbTrail(nav, trail) {
  nav.replaceChildren(...trail.flatMap((x, i) => {
    const el = i === trail.length - 1
      ? h('span.crumb', { 'aria-current': 'location', text: x.name })
      : h('button.crumb.linkbtn', { type: 'button', text: x.name, on: { click: x.go } });
    return i ? [h('span.crumb-sep', { 'aria-hidden': 'true', text: '/' }), el] : [el];
  }));
  return nav;
}

/**
 * A folder tree on the left and the selected folder's content on the right,
 * for a tree that is fully known up front (`buildTree()` from files.js): the
 * composer's file list and the recipient's file view.
 *
 * `renderPane(dir, { open })` returns the right pane's content for folder
 * `dir` (a buildTree node); `open(path)` shows a sub-folder and reveals it in
 * the tree. `state` restores a previous `{ selected, expanded }` (paths); a
 * folder that no longer exists falls back to its nearest remaining parent.
 */
export function folderBrowser({ label, rootName, root, renderPane, state = null, paneLabel = 'Folder contents' }) {
  const byPath = new Map();
  (function index(d) { byPath.set(d.path, d); for (const c of d.dirs.values()) index(c); })(root);
  const sorted = (d) => [...d.dirs.values()].sort((a, b) => a.name.localeCompare(b.name));

  let sel = state && typeof state.selected === 'string' ? state.selected : '';
  while (sel && !byPath.has(sel)) sel = parentPath(sel);
  const expanded = new Set(((state && state.expanded) || []).filter((p) => byPath.has(p)));
  for (let p = sel; p; p = parentPath(p)) expanded.add(parentPath(p));

  const crumbs = h('nav.crumbs', { 'aria-label': 'Folder path' });
  const body = h('div.browser-body');
  const pane = h('div.browser-pane', { role: 'region', 'aria-label': paneLabel }, crumbs, body);
  let current = '';

  const tree = createTree({
    label,
    root: { id: '', name: rootName },
    loadChildren: (path) => sorted(byPath.get(path)).map((d) => ({ id: d.path, name: d.name, leaf: d.dirs.size === 0 })),
    onSelect: (n) => show(n.id),
    selected: sel,
    expanded: [...expanded],
  });

  const ancestors = (path) => {
    const ids = [''];
    const segs = path ? path.split('/') : [];
    for (let i = 1; i <= segs.length; i++) ids.push(segs.slice(0, i).join('/'));
    return ids;
  };
  const open = async (path) => {
    await tree.reveal(ancestors(path));
    show(path);
  };

  function show(path) {
    const d = byPath.get(path);
    if (!d) return;
    current = path;
    crumbTrail(crumbs, ancestors(path).map((p) => ({ name: p ? byPath.get(p).name : rootName, go: () => open(p) })));
    body.replaceChildren(renderPane(d, { open }));
  }

  const el = h('div.browser', {}, h('div.browser-tree', {}, tree.el), pane);
  show(sel);
  return {
    el,
    tree,
    open,
    get current() { return current; },
    state: () => ({ selected: current, expanded: tree.state().expanded }),
  };
}
