# Accessibility checks for the console (GAP-REQ-09)

The Go tests (`go test ./internal/cp ./internal/webproxy`) check the contrast of every colour, the structure
the keyboard and screen-reader users rely on, and the shape of the pages a person sees when the proxy stops
them. They need no browser. The two scripts here need a browser and an `npm install`, so they are **not** part
of the regression run; run them after a change to the console.

```sh
cd test/a11y
npm init -y && npm i puppeteer-core axe-core        # Chrome or Chromium must be installed
go run ../../cmd/ztx-demo &                         # lab demo with sample data; it prints an admin token
node axe.js  <admin token>                          # prints "no violations", or each violation with where it is
node kb.js   <admin token>                          # sideways scrolling at 320 px, tab order, focus after a screen change
```

Set `BASE=http://host:port/` if the demo is not on 127.0.0.1:8099; set the Chrome path in the scripts if it is
not `/usr/bin/google-chrome`.

## What this does and does not show

* axe-core finds only the problems a program can find (usually a third to a half of the guidelines' failures).
  "No violations" is **not** a statement that the console conforms to WCAG 2.1 AA.
* Nothing here replaces trying the console with a screen reader (NVDA, VoiceOver, Orca), with the browser at
  200 percent zoom, with a keyboard only, and with a person who uses these tools every day. That has **not**
  been done. It belongs in `USABILITY-RUNBOOK.md` next to the other checks that need people.
* Checked by hand-written scripts in one browser (Chrome): the light and dark setting; 320 and 1180 pixel widths;
  Tab order; skip link; focus moved to the heading after a screen change.
