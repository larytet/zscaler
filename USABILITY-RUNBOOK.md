# Usability and manual test runbook

For the checks that need people: USE-001, USE-002, USE-003 (TEST-PLAN T3.4) and WBT-015 to WBT-020 (T4). Written so two people who did **not** build the product can run it without help from the builder. Do not ask the builder questions during a run: every question you would have asked is a finding, write it down.

Results go in `USABILITY-RESULTS.md` (create it from the template at the end). A run only counts toward the exit criteria (TEST-PLAN T3.7 item 7) if it was done by someone who did not write the product.

## Before you start

You need:
- A control plane, one enforcement node and one connector running (README, "Try it on one machine", or the `make build` binaries on a small server). The person running the test may use a helper to set these up, but the **setup steps themselves are part of USE-001**, so start the stopwatch before you read the README.
- A test identity provider account with two users, one in the group `all-staff` and one in `contractors`, and an identity provider that supports OIDC with PKCE (README).
- A private app to protect: any internal web page or TCP service.
- A clean machine for each operating system under test: a fresh user account on a laptop is enough. Windows, macOS and Linux are separate runs.
- A stopwatch (phone is fine) and this file open on another device.

Write down: date, who you are (role, not name), operating system and version, browser and version, and whether you have used security software before.

## USE-001: first protected user in under 30 minutes (SMB-001)

Goal: someone with IT basics and no security background gets one user protected, following only the README.

1. Start the stopwatch. You may read only `README.md` and the console's own text.
2. Set up the tenant, the identity provider, one private app and the safe-default policies. Install and enrol one connector. Enrol one agent on a clean machine and sign in.
3. Stop the stopwatch when the person can open the private app through the agent **and** is blocked from a site in a blocked category (use a test site you control, listed in the categories file).
4. Record: total minutes; minutes per step; every point where you stopped, re-read, guessed, or gave up; every error message and whether it told you what to do.

Pass: under 30 minutes, no help from the builder. Fail or partial: write the time and the three biggest delays. A pass by one person is not enough: two people must each pass, or the product is not "under 30 minutes" yet.

## USE-002: do the alerts make sense (SMB-003)

1. Cause five alerts: block the same user from the same app ten times; switch off disk encryption or the firewall on a test device (or use the posture stub as in the e2e scenarios); stop the connector for three minutes; ask for access that needs approval; restrict a user.
2. Without any documentation, read each alert (console Overview and the email) and answer: what happened, who is affected, what should I do.
3. Score each alert 0 (could not tell), 1 (partly), 2 (clear). Record the words you did not understand.

Pass: every alert scores 2 for "what to do", and no alert needs documentation to understand. Anything scored 0 is a defect.

## USE-003: the block page

1. As an end user, hit a blocked web category, a blocked upload (DLP), and an app you are not allowed to reach.
2. For each: can you tell what happened and who to contact, without asking anyone? Is the reference number visible? Does the page ever show the sensitive data you sent?

Pass: yes to the first two for all three, and never the data.

## WBT-015: installing the workspace (WB-001)

Not testable until installers exist (slice W4). Until then, record how long it takes a person to run the launcher by hand: install a Chromium-family browser, enrol (`ztx-agent enrol-workspace`), start (`ztx-agent workspace`). Note anything needing administrator rights.

## WBT-016 to WBT-020: the workspace with a real browser

On each operating system, with a visible window:

- **WBT-016 isolation.** Before starting, note your personal browser's bookmarks, saved passwords and extensions. Start the workspace. Confirm none of them appear. Open your personal browser at the same time: confirm it is unchanged and still works.
- **WBT-017 inspection trust.** With inspection on, open an HTTPS site in the workspace: it must load without a certificate warning, and you should note any message from the browser about unsupported command-line flags. Open the same site in your personal browser: it must show the original site certificate (click the padlock and read the issuer). Compare the operating system's trust store before and after (list trusted certificates, or note the count): it must not change.
- **WBT-018 data controls.** Not testable until the workspace extension exists (slice W3, blocked on a decision). Record "not yet built".
- **WBT-019 screenshots and screen sharing.** Try to take a screenshot and share the workspace window in a call, on this OS. Record what happens. Expect that it is **not** blocked; the console and the first-run text must not claim otherwise.
- **WBT-020 honest limits.** Read the first-run screen and the console text. Do they say, in plain words, that the workspace does not protect against a compromised operating system, a camera pointed at the screen, or a person retyping data (WB-013)? Currently the console text covers part of this; record what is missing.
- **Lock behaviour.** While the workspace is open: revoke the device in the console (it should close within about 30 seconds and the profile folder should disappear); turn off disk encryption or the firewall (it should close within the check interval); disconnect the network for longer than the grace period (it should close after that).

## A11Y-001: the console with assistive tools (GAP-REQ-09)

Do this with a person who uses a screen reader or a keyboard only every day if you can. Use the lab demo (`go run ./cmd/ztx-demo`, it prints a token) in the browser they use.

1. Sign in, then visit every screen, in the simple and in the advanced mode, using only the keyboard.
2. Repeat with a screen reader (NVDA on Windows, VoiceOver on macOS, Orca on Linux). Can they tell which screen they are on, read each table, and do the actions (restrict, revoke, approve, the policy simulator)?
3. Zoom the browser to 200 percent and to 400 percent. Is anything cut off or does it need sideways scrolling to read a line?
4. Trigger a block page (`curl -x http://127.0.0.1:3129 http://example-bad.test/` shows its text; in a browser use the agent's proxy) and read it with the screen reader.

Write down, for each problem: the screen, the tool and its version, what happened and what you expected.

## What to hand back

Fill in `USABILITY-RESULTS.md` using the template below. The builder reads it, files each finding as a defect, and updates `STATUS.md`. Do not edit code during a run.

```
# Usability results

| Test | Who (role) | OS and browser | Date | Result (pass/fail/partial) | Time | Notes and quotes |
|---|---|---|---|---|---|---|
| USE-001 | | | | | | |
| USE-002 | | | | | | |
| USE-003 | | | | | | |
| WBT-015 | | | | | | |
| WBT-016 | | | | | | |
| WBT-017 | | | | | | |
| WBT-019 | | | | | | |
| WBT-020 | | | | | | |
| Lock behaviour | | | | | | |

Top three things that confused or slowed me:
1.
2.
3.
```

## Known gaps you will hit (so you do not report them as surprises)

- The workspace extension (clipboard, download, upload, print, watermark controls) does not exist; its design is blocked on a decision.
- There are no installers: everything is run from the command line.
- Windows and macOS agents have had no real-device testing by the builder; the Windows firewall posture check is not implemented, so a Windows device may be reported as failing the baseline.
- The console was walked through in Chrome only.
