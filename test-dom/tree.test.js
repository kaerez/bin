// tree.test.js — the folder tree (public/js/tree.js): WAI-ARIA tree semantics,
// collapsed by default, + / − toggles, lazy children, roving tabindex and the
// keyboard model, plus the tree + right-pane folder browser.
import { describe, it, expect, beforeEach } from 'vitest';
import { createTree, folderBrowser } from '../public/js/tree.js';
import { buildTree } from '../public/js/files.js';

// a/ (a1/ (deep/), a2/), b/, c/ (empty)
const DIRS = {
  root: [{ id: 'a', name: 'a' }, { id: 'b', name: 'b' }, { id: 'c', name: 'c', leaf: true }],
  a: [{ id: 'a1', name: 'a1' }, { id: 'a2', name: 'a2' }],
  a1: [{ id: 'deep', name: 'deep' }],
  a2: [], b: [], deep: [],
};

const item = (tree, id) => tree.el.querySelector(`.tree-item[data-id="${id}"]`);
const key = (el, k) => el.dispatchEvent(new KeyboardEvent('keydown', { key: k, bubbles: true }));
const tick = () => new Promise((r) => setTimeout(r, 0));
const tabStops = (tree) => [...tree.el.querySelectorAll('.tree-item')].filter((li) => li.tabIndex === 0);

function make(opts = {}) {
  const calls = [];
  const selected = [];
  const tree = createTree({
    label: 'Folders',
    root: { id: 'root', name: 'My Drive' },
    loadChildren: (id) => { calls.push(id); return opts.async ? Promise.resolve(DIRS[id]) : DIRS[id]; },
    onSelect: (n) => selected.push(n),
    ...opts,
  });
  document.body.replaceChildren(tree.el);
  return { tree, calls, selected };
}

beforeEach(() => document.body.replaceChildren());

describe('createTree', () => {
  it('is a named tree; the root is open and every folder under it is closed', async () => {
    const { tree, calls } = make();
    await tree.ready;
    expect(tree.el.getAttribute('role')).toBe('tree');
    expect(tree.el.getAttribute('aria-label')).toBe('Folders');
    const root = item(tree, 'root');
    expect(root.getAttribute('role')).toBe('treeitem');
    expect(root.getAttribute('aria-expanded')).toBe('true');
    expect(root.getAttribute('aria-selected')).toBe('true');
    expect(root.getAttribute('aria-level')).toBe('1');
    const a = item(tree, 'a');
    expect(a.getAttribute('aria-expanded')).toBe('false');
    expect(a.getAttribute('aria-level')).toBe('2');
    expect(a.getAttribute('aria-setsize')).toBe('3');
    expect(a.getAttribute('aria-posinset')).toBe('1');
    expect(a.querySelector('.tree-group').hidden).toBe(true);
    expect(a.parentElement.getAttribute('role')).toBe('group');
    // Only the root was fetched: sub-folders load on demand.
    expect(calls).toEqual(['root']);
    // A known-empty folder has no toggle and no aria-expanded.
    expect(item(tree, 'c').hasAttribute('aria-expanded')).toBe(false);
    expect(item(tree, 'c').querySelector('.tree-twisty').textContent).toBe('');
    // The accessible name is the folder's own label, not its descendants.
    const lab = document.getElementById(a.getAttribute('aria-labelledby'));
    expect(lab.textContent).toBe('a');
    // The toggle is decorative for assistive technology (state is on the item).
    expect(a.querySelector('.tree-twisty').getAttribute('aria-hidden')).toBe('true');
    expect(a.querySelector('.tree-twisty').textContent).toBe('+');
  });

  it('collapsed root when asked', () => {
    const { tree, calls } = make({ rootExpanded: false });
    expect(item(tree, 'root').getAttribute('aria-expanded')).toBe('false');
    expect(calls).toEqual([]);
  });

  it('+ expands (lazily) and − collapses; an empty folder loses its toggle', async () => {
    const { tree, calls, selected } = make();
    const a = item(tree, 'a');
    a.querySelector('.tree-twisty').click();
    expect(a.getAttribute('aria-expanded')).toBe('true');
    expect(a.querySelector('.tree-twisty').textContent).toBe('−');
    expect(item(tree, 'a1')).not.toBeNull();
    expect(calls).toEqual(['root', 'a']);
    // Toggling does not select (the right pane stays where it is).
    expect(selected).toEqual([]);
    a.querySelector('.tree-twisty').click();
    expect(a.getAttribute('aria-expanded')).toBe('false');
    expect(a.querySelector('.tree-group').hidden).toBe(true);
    // b turns out to be empty.
    item(tree, 'b').querySelector('.tree-twisty').click();
    expect(item(tree, 'b').hasAttribute('aria-expanded')).toBe(false);
    // Expanding again does not refetch.
    a.querySelector('.tree-twisty').click();
    expect(calls.filter((c) => c === 'a')).toHaveLength(1);
  });

  it('async children: busy while loading', async () => {
    const { tree } = make({ async: true });
    await tree.ready;
    const a = item(tree, 'a');
    a.querySelector('.tree-twisty').click();
    expect(a.getAttribute('aria-busy')).toBe('true');
    await tick();
    expect(a.hasAttribute('aria-busy')).toBe(false);
    expect(a.getAttribute('aria-expanded')).toBe('true');
    expect(item(tree, 'a2')).not.toBeNull();
  });

  it('selecting a folder (click) calls back with its path', async () => {
    const { tree, selected } = make();
    await tree.expand('a');
    item(tree, 'a1').querySelector('.tree-label').click();
    expect(selected.at(-1)).toEqual({ id: 'a1', name: 'a1', path: [{ id: 'root', name: 'My Drive' }, { id: 'a', name: 'a' }, { id: 'a1', name: 'a1' }] });
    expect(item(tree, 'a1').getAttribute('aria-selected')).toBe('true');
    expect(item(tree, 'root').getAttribute('aria-selected')).toBe('false');
    expect(document.activeElement).toBe(item(tree, 'a1'));
  });

  it('roving tabindex: exactly one tab stop', async () => {
    const { tree } = make();
    await tree.ready;
    expect(tabStops(tree)).toEqual([item(tree, 'root')]);
    tree.focus();
    key(item(tree, 'root'), 'ArrowDown');
    expect(document.activeElement).toBe(item(tree, 'a'));
    expect(tabStops(tree)).toEqual([item(tree, 'a')]);
  });

  it('keyboard: arrows, Home/End, Right/Left, Enter/Space, * and type-ahead', async () => {
    const { tree, selected } = make();
    await tree.ready;
    tree.focus();
    const at = () => document.activeElement.dataset.id;
    key(document.activeElement, 'ArrowDown'); expect(at()).toBe('a');
    key(document.activeElement, 'ArrowRight'); // expands
    expect(item(tree, 'a').getAttribute('aria-expanded')).toBe('true');
    expect(at()).toBe('a');
    key(document.activeElement, 'ArrowRight'); expect(at()).toBe('a1'); // first child
    key(document.activeElement, 'ArrowDown'); expect(at()).toBe('a2');
    key(document.activeElement, 'ArrowLeft'); expect(at()).toBe('a'); // to parent
    key(document.activeElement, 'ArrowLeft'); // collapses
    expect(item(tree, 'a').getAttribute('aria-expanded')).toBe('false');
    key(document.activeElement, 'ArrowDown'); expect(at()).toBe('b'); // a's children are hidden
    key(document.activeElement, 'End'); expect(at()).toBe('c');
    key(document.activeElement, 'Home'); expect(at()).toBe('root');
    key(document.activeElement, 'ArrowUp'); expect(at()).toBe('root');
    key(document.activeElement, 'b'); expect(at()).toBe('b'); // type-ahead
    key(document.activeElement, 'Enter');
    expect(selected.at(-1).id).toBe('b');
    key(document.activeElement, 'ArrowUp');
    key(document.activeElement, ' ');
    expect(selected.at(-1).id).toBe('a');
    key(document.activeElement, '*'); // expands all siblings
    expect(item(tree, 'a').getAttribute('aria-expanded')).toBe('true');
  });

  it('collapsing a folder moves focus out of its hidden children', async () => {
    const { tree } = make();
    await tree.expand('a');
    item(tree, 'a1').focus();
    item(tree, 'a').querySelector('.tree-twisty').click();
    expect(document.activeElement).toBe(item(tree, 'a'));
    expect(tabStops(tree)).toHaveLength(1);
  });

  it('reveal, refresh, setChildren and state', async () => {
    const { tree, selected } = make();
    await tree.reveal(['root', 'a', 'a1', 'deep'], { notify: true });
    expect(selected.at(-1).id).toBe('deep');
    expect(item(tree, 'a1').getAttribute('aria-expanded')).toBe('true');
    expect(tree.state()).toEqual({ selected: 'deep', expanded: ['root', 'a', 'a1'] });
    // Rename and remove through setChildren; the removed selection falls back to its parent.
    tree.setChildren('a', [{ id: 'a2', name: 'a-two' }]);
    expect(item(tree, 'a2').querySelector('.tree-text').textContent).toBe('a-two');
    expect(item(tree, 'a1')).toBeNull();
    expect(selected.at(-1).id).toBe('a');
    // refresh re-reads the loader.
    DIRS.b = [{ id: 'b1', name: 'b1' }];
    await tree.refresh('b');
    await tree.expand('b');
    expect(item(tree, 'b1')).not.toBeNull();
    DIRS.b = [];
    // restoring a state
    const again = make({ expanded: ['root', 'a'], selected: 'a2' });
    await again.tree.ready;
    expect(item(again.tree, 'a').getAttribute('aria-expanded')).toBe('true');
    expect(item(again.tree, 'a2').getAttribute('aria-selected')).toBe('true');
  });

  it('a failed load reports the error and stays collapsed', async () => {
    const errors = [];
    const tree = createTree({ label: 'x', root: { id: 'r', name: 'r' }, loadChildren: (id) => (id === 'r' ? [{ id: 'k', name: 'k' }] : Promise.reject(new Error('offline'))), onError: (e) => errors.push(e.message) });
    document.body.replaceChildren(tree.el);
    await tree.expand('k');
    expect(errors).toEqual(['offline']);
    expect(item(tree, 'k').getAttribute('aria-expanded')).toBe('false');
  });

  it('names are text, never markup', () => {
    const tree = createTree({ label: 'x', root: { id: 'r', name: '<img src=x onerror=alert(1)>' }, loadChildren: () => [] });
    expect(tree.el.querySelector('img')).toBeNull();
    expect(tree.el.querySelector('.tree-text').textContent).toBe('<img src=x onerror=alert(1)>');
  });
});

describe('folderBrowser', () => {
  const entries = [
    { path: 'top.txt', size: 1 }, { path: 'docs/a.md', size: 2 }, { path: 'docs/sub/b.bin', size: 3 }, { path: 'empty', dir: true },
  ];
  const pane = (d, { open }) => {
    const ul = document.createElement('ul');
    for (const c of d.dirs.values()) { const b = document.createElement('button'); b.className = 'open'; b.textContent = c.name; b.onclick = () => open(c.path); ul.append(b); }
    for (const f of d.files) { const li = document.createElement('li'); li.className = 'file'; li.textContent = f.path; ul.append(li); }
    return ul;
  };
  const files = (b) => [...b.el.querySelectorAll('.browser-pane .file')].map((x) => x.textContent);

  it('shows the root folder content on the right and a collapsed tree on the left', () => {
    const b = folderBrowser({ label: 'Folders', rootName: 'All files', root: buildTree(entries), renderPane: pane });
    document.body.replaceChildren(b.el);
    expect(files(b)).toEqual(['top.txt']);
    expect(b.el.querySelector('.browser-pane').getAttribute('role')).toBe('region');
    const docs = b.el.querySelector('.tree-item[data-id="docs"]');
    expect(docs.getAttribute('aria-expanded')).toBe('false');
    expect(b.el.querySelector('.crumbs [aria-current="location"]').textContent).toBe('All files');
  });

  it('selecting a folder in the tree or opening it from the pane shows its content', async () => {
    const b = folderBrowser({ label: 'Folders', rootName: 'All files', root: buildTree(entries), renderPane: pane });
    document.body.replaceChildren(b.el);
    b.el.querySelector('.tree-item[data-id="docs"] .tree-label').click();
    expect(files(b)).toEqual(['docs/a.md']);
    b.el.querySelector('.browser-pane .open').click(); // sub
    await tick();
    expect(files(b)).toEqual(['docs/sub/b.bin']);
    expect(b.el.querySelector('.tree-item[data-id="docs/sub"]').getAttribute('aria-selected')).toBe('true');
    expect(b.el.querySelector('.tree-item[data-id="docs"]').getAttribute('aria-expanded')).toBe('true');
    expect([...b.el.querySelectorAll('.crumbs .crumb')].map((c) => c.textContent)).toEqual(['All files', 'docs', 'sub']);
    // Breadcrumb back up.
    b.el.querySelector('.crumbs button.crumb').click();
    await tick();
    expect(files(b)).toEqual(['top.txt']);
  });

  it('restores its state, falling back to the nearest remaining folder', async () => {
    const b = folderBrowser({ label: 'F', rootName: 'All', root: buildTree(entries), renderPane: pane, state: { selected: 'docs/sub/gone', expanded: ['', 'docs'] } });
    document.body.replaceChildren(b.el);
    await b.tree.ready;
    expect(b.current).toBe('docs/sub');
    expect(files(b)).toEqual(['docs/sub/b.bin']);
    expect(b.state()).toEqual({ selected: 'docs/sub', expanded: ['', 'docs'] });
  });
});
