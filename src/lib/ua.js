// ua.js — a small, conservative User-Agent reader for read receipts: browser
// family + major version and operating system. Unknown input yields
// "other"; nothing here is trusted for security (a client can send anything).

const BROWSERS = [
  ['Edge', /\bEdgA?\/(\d+)/], ['Edge', /\bEdgiOS\/(\d+)/], ['Opera', /\bOPR\/(\d+)/], ['Samsung Internet', /\bSamsungBrowser\/(\d+)/],
  ['Chrome (headless)', /\bHeadlessChrome\/(\d+)/], ['Chrome', /\bCriOS\/(\d+)/], ['Firefox', /\bFxiOS\/(\d+)/], ['Firefox', /\bFirefox\/(\d+)/],
  ['Chrome', /\bChrome\/(\d+)/], ['Safari', /\bVersion\/(\d+)[^ ]* (?:Mobile\/\S+ )?Safari\//],
  ['secbin CLI', /\bsecbin(?:-cli)?\/(\d+)/], ['curl', /\bcurl\/(\d+)/],
];
const SYSTEMS = [
  ['iOS', /\b(?:iPhone|iPad|iPod)\b.*? OS (\d+)/], ['Android', /\bAndroid (\d+)/], ['ChromeOS', /\bCrOS\b/],
  ['Windows', /\bWindows NT (\d+)/], ['macOS', /\bMac OS X (\d+)/], ['Linux', /\bLinux\b/],
];

const clip = (s, n) => String(s || '').slice(0, n);

/** { browser, version, os } — all short strings ("" when unknown). */
export function parseUserAgent(ua) {
  const s = clip(ua, 512);
  let browser = s ? 'other' : '';
  let version = '';
  for (const [name, re] of BROWSERS) {
    const m = re.exec(s);
    if (m) { browser = name; version = m[1] || ''; break; }
  }
  let os = s ? 'other' : '';
  for (const [name, re] of SYSTEMS) {
    const m = re.exec(s);
    if (m) {
      os = name;
      if (name === 'Windows' && m[1]) os = `Windows ${m[1] === '10' ? '10/11' : m[1]}`;
      else if (m[1]) os = `${name} ${m[1]}`;
      break;
    }
  }
  return { browser, version: clip(version, 8), os: clip(os, 32) };
}

/** The first few languages of Accept-Language ("he-IL, en-US"), bounded. */
export function parseLanguages(header) {
  return clip(header, 200).split(',').map((p) => p.split(';')[0].trim()).filter((t) => /^[A-Za-z]{1,8}(-[A-Za-z0-9]{1,8})*$/.test(t)).slice(0, 5).join(', ');
}
