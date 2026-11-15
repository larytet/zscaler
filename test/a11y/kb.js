// Checks that no screen makes the whole page scroll sideways at 320 and 1180 pixels, that the first Tab stop is the skip
// link, that every screen button can be reached with Tab, and that Enter on a screen button moves focus to its heading.
const puppeteer = require('puppeteer-core');
(async () => {
  const token = process.argv[2];
  const b = await puppeteer.launch({ executablePath: '/usr/bin/google-chrome', headless: 'new', args: ['--no-sandbox'] });
  const labels = ['Overview', 'Incidents', 'Access', 'People', 'Apps', 'Approvals', 'Inspection', 'Policy', 'Reports', 'Investigate', 'Versions'];
  for (const width of [320, 1180]) {
    const wide = [];
    for (const label of labels) {
      const p = await b.newPage();
      await p.setViewport({ width, height: 700, deviceScaleFactor: width === 320 ? 2 : 1 });
      await p.evaluateOnNewDocument((t) => { sessionStorage.setItem('ztx-token', t); localStorage.setItem('ztx-mode', 'advanced'); }, token);
      await p.goto(process.env.BASE || 'http://127.0.0.1:8099/', { waitUntil: 'networkidle0' });
      await p.evaluate((l) => { [...document.querySelectorAll('#tabs button')].find((x) => x.textContent === l).click(); }, label);
      await new Promise((r) => setTimeout(r, 700));
      const m = await p.evaluate(() => ({ sw: document.documentElement.scrollWidth, cw: document.documentElement.clientWidth }));
      if (m.sw > m.cw + 1) wide.push(label + ' (' + m.sw + ' > ' + m.cw + ')');
      await p.close();
    }
    console.log('width ' + width + ': pages that scroll sideways as a whole:', wide.length ? wide.join(', ') : 'none');
  }
  // keyboard: the first Tab stops on the skip link, Enter on it moves into the content, every nav button is reachable, no trap
  const p = await b.newPage();
  await p.setViewport({ width: 1180, height: 800 });
  await p.evaluateOnNewDocument((t) => { sessionStorage.setItem('ztx-token', t); localStorage.setItem('ztx-mode', 'advanced'); }, token);
  await p.goto(process.env.BASE || 'http://127.0.0.1:8099/', { waitUntil: 'networkidle0' });
  await new Promise((r) => setTimeout(r, 800));
  const seen = [];
  for (let i = 0; i < 40; i++) {
    await p.keyboard.press('Tab');
    seen.push(await p.evaluate(() => { const e = document.activeElement; return e ? (e.tagName + ':' + (e.textContent || e.getAttribute('aria-label') || '').trim().slice(0, 24)) : 'none'; }));
  }
  console.log('first stops:', seen.slice(0, 6).join(' | '));
  const navHits = labels.filter((l) => seen.some((s) => s === 'BUTTON:' + l)).length;
  console.log('nav buttons reached by Tab within 40 stops:', navHits + '/' + labels.length, '; distinct stops:', new Set(seen).size);
  // activate a screen with the keyboard only
  await p.evaluate(() => document.activeElement && document.activeElement.blur());
  await p.focus('#tabs button:nth-child(4)');
  await p.keyboard.press('Enter');
  await new Promise((r) => setTimeout(r, 800));
  console.log('after Enter on a nav button, focus is on:', await p.evaluate(() => document.activeElement.tagName + ':' + document.activeElement.textContent.slice(0, 30)));
  await b.close();
})().catch((e) => { console.error(e); process.exit(1); });
