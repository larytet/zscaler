// Runs axe-core (WCAG 2.0/2.1 A and AA rules plus best practices) on every console screen, in the light and the dark
// setting and in the simple and the advanced mode. See README.md in this directory.
const puppeteer = require('puppeteer-core');
const fs = require('fs');
(async () => {
  const token = process.argv[2];
  const axeSrc = fs.readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8');
  const b = await puppeteer.launch({ executablePath: '/usr/bin/google-chrome', headless: 'new', args: ['--no-sandbox'] });
  const result = {};
  for (const scheme of ['light', 'dark']) {
    for (const mode of ['simple', 'advanced']) {
      const labels = mode === 'simple' ? ['Alerts', 'Users', 'Apps'] : ['Overview', 'Incidents', 'Access', 'People', 'Apps', 'Approvals', 'Inspection', 'Policy', 'Reports', 'Investigate', 'Versions'];
      for (const label of labels) {
        const p = await b.newPage();
        await p.setViewport({ width: 1180, height: 800 });
        await p.emulateMediaFeatures([{ name: 'prefers-color-scheme', value: scheme }]);
        await p.evaluateOnNewDocument((t, m) => { sessionStorage.setItem('ztx-token', t); localStorage.setItem('ztx-mode', m); }, token, mode);
        await p.goto(process.env.BASE || 'http://127.0.0.1:8099/', { waitUntil: 'networkidle0' });
        await p.evaluate((l) => { [...document.querySelectorAll('#tabs button')].find((x) => x.textContent === l).click(); }, label);
        await new Promise((r) => setTimeout(r, 900));
        await p.evaluate(axeSrc);
        const r = await p.evaluate(() => axe.run(document, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'best-practice'] } }));
        for (const v of r.violations) {
          const k = v.id + ' [' + v.impact + '] ' + v.help;
          result[k] = result[k] || { tags: v.tags.filter((t) => t.startsWith('wcag') || t === 'best-practice'), where: new Set(), nodes: new Set() };
          result[k].where.add(scheme + '/' + mode + '/' + label);
          v.nodes.slice(0, 2).forEach((n) => result[k].nodes.add(n.target.join(' ') + ' :: ' + (n.failureSummary || '').split('\n').slice(0, 2).join(' ').slice(0, 160)));
        }
        await p.close();
      }
    }
  }
  await b.close();
  for (const [k, v] of Object.entries(result)) console.log(k, '\n  ', v.tags.join(','), '\n   in:', [...v.where].slice(0, 6).join('; '), '(' + v.where.size + ' screens)\n   e.g.', [...v.nodes].slice(0, 2).join('\n        '));
  if (!Object.keys(result).length) console.log('no violations');
})().catch((e) => { console.error(e); process.exit(1); });
