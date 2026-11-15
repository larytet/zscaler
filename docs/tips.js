"use strict";
// Tooltips for the demo pages. Hover or keyboard focus shows a short explanation.
// Tips are attached automatically from the rules below, so they follow re-renders.
(function () {
  const page = document.body.dataset.page || "console";
  const txt = (el) => el.textContent.trim().replace(/\s+/g, " ");
  const byPrefix = (table) => (el) => { const t = txt(el).toLowerCase(); for (const [p, tip] of table) if (t.startsWith(p.toLowerCase())) return tip; return null; };

  const BADGE = {
    built: "Built: this works in the code today, in a basic form.",
    basic: "Built, basic: it works, but with known limits listed in the requirements.",
    proposed: "Proposed: written in the requirements (section 19) but not built yet.",
  };

  const TABS = {
    agents: "AI agents: identities, approvals, volume caps and the safety check.",
    aiuse: "AI tool use: which AI tools staff use and what they paste into them.",
    audit: "Audit log: a record of every action that nobody can quietly edit.",
    today: "Today: what needs your attention now, in plain words.",
    people: "People and devices: who is enrolled and how healthy each device is.",
    contractors: "Contractor access: give an outsider one app for a few hours.",
    sim: "Policy simulator: see who would gain or lose access before you save a rule.",
    why: "Why was I blocked?: a plain-language reason and the fix.",
    byod: "Personal devices: the workspace browser (proof of concept).",
    reports: "Reports: the weekly summary and insurance evidence.",
  };

  const KPI = [
    ["Access decisions", "Allow and block decisions made by the gatekeeper today. The line shows the last 7 days."],
    ["AI agent calls", "Requests that AI agents made in the last day. The line shows the last 7 days."],
    ["Agent calls", "Requests that AI agents made in the last 24 hours. The line shows the last 7 days."],
    ["Blocked", "Agent requests refused by a rule or a volume cap."],
    ["Writes held", "Changes agents asked for that are waiting for a person to approve."],
    ["Waiting for approval", "Requests held until you approve or deny them."],
    ["Values masked", "Sensitive values replaced with tokens before an agent saw them."],
    ["Devices below baseline", "Devices that fail the minimum health check, for example no disk encryption."],
  ];

  const ACT = {
    ask: "Emails the person the steps to turn on disk encryption (demo: nothing is sent).",
    restrict: "Moves the person to a restricted group that is denied first. Live sessions end within seconds.",
    unrestrict: "Puts the person back into their normal groups.",
    review: "Opens the person's access list so you can see what they can reach (demo).",
    disable: "Turns the account off everywhere. Sessions end within seconds.",
    remind: "Sends staff a short reminder (demo: nothing is sent).",
    dismiss: "Closes the alert. The action is written to the audit log.",
    revoke: "Kills this device's certificate. It stops working within seconds.",
    approve: "Allows this exact request once. The permission expires after 15 minutes.",
    deny: "Refuses the request. The agent is told no.",
    revokeagent: "Ends this agent's access now.",
    killall: "Emergency stop: revokes every agent at once.",
    burst: "Simulates the agent reading 200 more records so you can see the cap work.",
    capreset: "Resets the counter and lets the agent run again.",
    killshare: "Switches this contractor link off immediately.",
  };

  const BTN_ID = {
    mklink: "Creates a time-boxed link for one app (a demo link, not a real one).",
    inj: "Shows what the agent sends and what the platform sends on after adding the key.",
    inj2: "Shows what happens when a hidden instruction tells the agent to reveal its key.",
    dlpgo: "Scans the text for card numbers, IBANs, national IDs, keys and emails.",
    dlpsample: "Fills the box with sample text that contains sensitive data.",
    simgo: "Replays recent decisions against the draft change and lists who would lose access.",
    wgo: "Explains the decision for this person and app, with the fix.",
    launch: "Starts a workspace session step by step (demo).",
    dl: "Downloads this table as a text file (stays on your computer).",
    verify: "Recomputes every line's hash and reports the first line that does not match.",
    tamper: "Edits an old log line so you can see Verify catch it.",
  };

  const WIZ = {
    start: "Opens the wizard that creates a new AI agent identity.",
    next: "Goes to the next step.",
    back: "Goes back one step.",
    cancel: "Leaves the wizard without creating anything.",
    create: "Creates the agent and adds it to the registry (demo only).",
    addcrit: "Adds another condition. Conditions are joined by AND.",
    rmcrit: "Removes this whole condition.",
    rmval: "Removes this value from the condition.",
  };

  const SEG = {
    "chartMode:both": "Show allowed and blocked calls together.",
    "chartMode:allowed": "Show only allowed calls.",
    "chartMode:blocked": "Show only blocked calls.",
    "wmode:deny": "Agents can read only. Every change is refused.",
    "wmode:ask": "Agents read freely. Every change waits for a person.",
    "wmode:allow": "Agents can change data without asking. Not recommended.",
    "wiz.writes:deny": "This agent can never change data.",
    "wiz.writes:ask": "Changes by this agent wait for its owner.",
    "wiz.writes:allow": "This agent can change data without asking.",
    "ai:Allow": "Let staff use this tool with no interruption.",
    "ai:Warn": "Show a warning page first. The user may continue.",
    "ai:Block": "Refuse the request and show a block page.",
  };

  const TH = {
    person: "A person from your identity provider. The line below the name is their role.",
    device: "The device the agent reports on. Posture comes from a signed report.",
    "disk encrypted": "Needed for Payroll and the accounting database. No means a lost device could expose data.",
    "risk (0-100)": "A score from a few fixed rules, such as device health and blocked attempts. The reason is under the number.",
    status: "active, restricted (denied first) or disabled.",
    agent: "An AI agent. It has its own identity and acts for its owner.",
    owner: "The person responsible for the agent. If they leave, the agent should go too.",
    apps: "The apps this agent is allowed to reach.",
    "last used": "When the agent last made a request. Unused agents should be removed.",
    "access ends": "When the agent's access stops by itself. \"never\" is flagged as a risk.",
    tool: "An AI tool seen in your network traffic.",
    people: "How many staff used the tool.",
    "last 7 days": "Prompts and uploads in the last week.",
    setting: "What happens when someone uses this tool: allow, warn or block.",
    "time (utc)": "When the event was recorded.",
    event: "What happened, in plain words.",
    "hash (first 10)": "Fingerprint of this line plus the previous line. Change any earlier line and later fingerprints stop matching.",
    question: "A question that typically appears on a cyber-insurance form.",
    "answer from this product": "What this product can prove. Things it cannot see are marked not evidenced.",
  };

  const HEAD = [
    ["today", "Open items first. Each one says what happened, why it matters and gives one action."],
    ["people and devices", "Everyone enrolled, with device health and a risk score."],
    ["contractor access", "Short-lived access for outsiders, limited to one app."],
    ["ai agents", "AI agents get their own identity, tied to the person who owns them."],
    ["agent activity", "Calls per day for the last week, from sample data."],
    ["default for every agent", "The baseline rule for what agents may change."],
    ["registry", "Every agent, who owns it, what it reaches and when its access ends."],
    ["waiting for your approval", "Writes that agents asked for. Read the exact request before you approve."],
    ["the agent never holds the password", "The platform keeps the key and adds it after the rules say yes."],
    ["volume cap", "Limits how much an agent may read per hour, plus an emergency stop."],
    ["dangerous setup", "Warns when one agent can read private data, read untrusted input and send data out."],
    ["ai tool use", "Which AI tools staff use, and what they paste."],
    ["try the paste scanner", "Type or paste text to see what the scanner finds. Nothing leaves this page."],
    ["policy simulator", "Preview a rule change before you save it."],
    ["why was i blocked", "Pick a person and an app to get the reason and the fix."],
    ["personal devices", "A workspace browser for personal or contractor devices. Proof of concept."],
    ["in v1", "What the first version of the workspace browser does."],
    ["deferred", "What is left for a later version."],
    ["reports", "Summaries you can send to the owner or to an insurer."],
    ["weekly digest", "A short weekly summary that an owner can read in a minute."],
    ["insurance evidence", "Answers for a cyber-insurance form. It marks what it cannot see."],
    ["audit log", "Every action in this demo is recorded here with a chained hash."],
    ["add ai agent", "Five steps: identity, apps, rules, review, create."],
    ["safety check", "Checks the agent against the three-part danger rule."],
  ];

  const LABEL = [
    ["who", "The outside person who gets the link."],
    ["app", "The one app the link opens."],
    ["hours", "How long the link works, from 1 to 72 hours."],
    ["agent name", "A short, unique name that appears in the audit log."],
    ["owner", "The person responsible. The agent can never do more than this person."],
    ["access ends after", "Access always ends. The owner renews it."],
    ["draft change", "The rule change to simulate."],
    ["person", "Whose access to explain."],
    ["type or paste", "Text to scan. It stays in your browser."],
    ["when the agent wants", "What happens when the agent tries to change data."],
    ["reads private data", "Can this agent see invoices, customers or other private records?"],
    ["reads untrusted input", "Can it read content from outside, such as inbound mail or web pages?"],
    ["can send data out", "Can it send mail, post to the web or change records without asking?"],
  ];

  const CRUMB = {
    identity: "Name the agent, pick its owner and set when access ends.",
    apps: "Choose the apps. The owner cap removes any the owner cannot reach.",
    rules: "Build the conditions that must all match.",
    review: "Read the rule as a sentence and see the safety check.",
    create: "Confirm and create.",
  };

  const consoleRules = [
    [".top .brand", () => "A demo of a small-business zero-trust console. All data is fictional."],
    ["nav a[href='index.html']", () => "This page: the clickable console mock."],
    ["nav a[href='how.html']", () => "Flow diagrams that show how the security works."],
    [".banner", () => "Everything on this page is made up. Nothing is sent or stored."],
    ["[data-tab]", (el) => TABS[el.dataset.tab]],
    [".tag.built", () => BADGE.built], [".tag.basic", () => BADGE.basic], [".tag.proposed", () => BADGE.proposed],
    [".tag:not(.built):not(.basic):not(.proposed)", (el) => /only$/.test(txt(el)) ? "The single app this link opens." : "Why this request was flagged for your attention."],
    [".kpi", (el) => byPrefix(KPI)(el.firstElementChild)],
    [".score", () => "Demo score: starts at 100 and drops for each open alert, unencrypted device and agent with no end date."],
    [".bar", (el) => el.closest(".card") && /Cap:/.test(el.closest(".card").textContent) ? "How much of the hourly record cap is used." : "The score out of 100."],
    ["[data-act]", (el) => ACT[el.dataset.act.split(":")[0]]],
    ["button[id]", (el) => BTN_ID[el.id]],
    ["[data-wiz]", (el) => WIZ[el.dataset.wiz.split(":")[0]]],
    ["[data-seg]", (el) => { const k = el.dataset.seg; return SEG[k] || SEG[k.replace(/^ai\.[a-z]+/, "ai")]; }],
    [".seg", () => "Choose one option."],
    ["svg[role=img]", () => "Calls per day for the last 7 days (sample data)."],
    [".legend span", () => "Colour key for the chart lines."],
    [".crumbs li", (el) => CRUMB[txt(el).toLowerCase()]],
    [".crit", () => "One condition. The values inside match if any one is true (OR)."],
    [".chip", () => "A value in this condition. Click the x to remove it."],
    [".and-box", () => "AND: every condition must be true."],
    [".or", () => "OR: either value is enough."],
    ["select[data-wadd]", () => "Add another value to this condition."],
    ["#addcrit", () => "Pick a new kind of condition to add."],
    ["label", byPrefix(LABEL)],
    ["input, select, textarea", (el) => { const l = el.labels && el.labels[0]; return l ? (l.getAttribute("data-tip") || byPrefix(LABEL)(l)) : null; }],
    [".check", () => "Tick to allow this app. Greyed out means the owner has no access to it."],
    ["article.card h3", () => "One alert. The text below says why it matters and what to do."],
    ["h1, h2, h3", byPrefix(HEAD)],
    ["th", (el) => TH[txt(el).toLowerCase()]],
    ["td", (el) => { const tb = el.closest("table"); if (!tb || !txt(el)) return null; const th = tb.querySelectorAll("th")[el.cellIndex]; return th ? TH[txt(th).toLowerCase()] : null; }],
    [".mono", () => "A raw technical value, shown as the system sees it."],
    [".pill-ok", () => "Green means fine."], [".pill-bad", () => "Red means it needs action."], [".pill-warn", () => "Amber means take a look."],
    [".reveal", () => "A preview of the request or text being discussed."],
  ];

  const howRules = [
    ["nav a[href='index.html']", () => "The clickable console mock."],
    ["nav a[href='how.html']", () => "This page: flow diagrams of the design."],
    [".banner", () => "Diagrams follow DESIGN.md and REQUIREMENTS.md section 19."],
    [".tag.built", () => BADGE.built], [".tag.basic", () => BADGE.basic], [".tag.proposed", () => BADGE.proposed],
    ["h2", () => "A group of diagrams."],
    ["h3", () => "One flow. The badge says whether it is built or proposed."],
    [".diagram", () => "Drawn in your browser from text. Scroll sideways if it is wide."],
    [".keypoints li", () => "A point to take away from the diagram above."],
  ];

  const rules = page === "how" ? howRules : consoleRules;
  function applyTips(root) {
    for (const [sel, fn] of rules) {
      root.querySelectorAll(sel).forEach((el) => {
        if (el.hasAttribute("data-tip")) return;
        let t = null; try { t = fn(el); } catch (e) { t = null; }
        if (t) el.setAttribute("data-tip", t);
      });
    }
  }
  window.applyTips = applyTips;

  // ----- the tooltip itself -----
  const tip = document.createElement("div");
  tip.id = "tip"; tip.className = "tip hidden"; tip.setAttribute("role", "tooltip");
  document.body.appendChild(tip);
  let cur = null, pending = null, timer = 0, auto = 0;
  const place = (el) => {
    const r = el.getBoundingClientRect();
    tip.style.left = "0px"; tip.style.top = "0px";
    const w = tip.offsetWidth, h = tip.offsetHeight;
    let x = r.left + r.width / 2 - w / 2; x = Math.max(8, Math.min(x, window.innerWidth - w - 8));
    let y = r.top - h - 8; if (y < 8) y = r.bottom + 8;
    tip.style.left = x + "px"; tip.style.top = y + "px";
  };
  const show = (el) => { const t = el.getAttribute("data-tip"); if (!t) return; cur = el; tip.textContent = t; tip.classList.remove("hidden"); el.setAttribute("aria-describedby", "tip"); place(el); };
  const hide = () => { clearTimeout(timer); clearTimeout(auto); pending = null; if (cur) { cur.removeAttribute("aria-describedby"); cur = null; } tip.classList.add("hidden"); };
  const target = (e) => (e.target && e.target.closest ? e.target.closest("[data-tip]") : null);
  document.addEventListener("mouseover", (e) => { const el = target(e); if (el === cur || el === pending) return; hide(); if (el) { pending = el; timer = setTimeout(() => show(el), 250); } });
  document.addEventListener("mouseout", (e) => { const to = e.relatedTarget && e.relatedTarget.closest ? e.relatedTarget.closest("[data-tip]") : null; if (to !== cur && to !== pending) hide(); });
  document.addEventListener("focusin", (e) => { const el = target(e); hide(); if (el) show(el); });
  document.addEventListener("focusout", hide);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") hide(); });
  document.addEventListener("click", (e) => { if (e.target.closest && e.target.closest("button")) hide(); });
  window.addEventListener("scroll", hide, true);
  document.addEventListener("pointerdown", (e) => {
    if (e.pointerType !== "touch") return;
    const el = target(e); hide();
    if (el && !el.closest("button, a, input, select, textarea")) { show(el); auto = setTimeout(hide, 3500); }
  });

  let queued = false;
  const schedule = () => { if (queued) return; queued = true; setTimeout(() => { queued = false; applyTips(document); }, 0); };
  new MutationObserver(schedule).observe(document.body, { childList: true, subtree: true });
  applyTips(document);
})();
