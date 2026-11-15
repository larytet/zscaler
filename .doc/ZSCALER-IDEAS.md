# Low-hanging ideas for Zscaler

Drawn from the Zscaler data sheets and reference architectures in `.doc/zscaler/`, read against what Cato Networks and Palo Alto Networks publish (`.doc/cato/`, `.doc/paloalto/`). The product-side analysis is in `../COMPETITIVE-ANALYSIS.md` and `../REQUIREMENTS.md`.

**Confidence.** Facts from the sources are marked `[V]` with the source. Everything else is my inference (`[I]`). Nothing here comes from Zscaler internals, so the effort estimates are guesses by an outsider and need checking. Pricing is not published in any source I read.

Ranked by value for effort. "Low-hanging" means mostly packaging, defaults, UX and content on top of capabilities Zscaler already has.

---

## 1. Packaging and pricing

### 1.1 Remove the 500-user minimums for an SMB tier
- **Observation `[V]`:** ZPA inside ZIA Essentials is "1 user per 20 subscribed users (Min: 500)". Third-party access, business-continuity cloud and deception each have a 500-user minimum. VPN service edges start at 50. Cloud NSS log streaming is gated above 500 users. App segments are capped at 10 (Essentials) or 20. (DS-ZIA, DS-ZPA)
- **Idea:** An SMB bundle with no seat minimums on ZPA and the add-ons above, and soft fair-use limits instead of segment caps.
- **Why it is cheap `[I]`:** a licensing change, no engineering.
- **Risk:** the August 2026 SMB initiative may already do part of this. Its numbers are not public.

### 1.2 Public per-user price list
- **Observation `[V]`:** quote-only through account teams. Cato and Palo Alto SMB-oriented offers are also partner-sold `[I]`.
- **Idea:** publish list prices for the SMB bundle. This is a strong signal to MSPs and to buyers who stop at "contact sales".

### 1.3 Three clear tiers
- **Observation `[V]`:** ZIA has Essentials and Platform. ZPA has four editions. Add-ons are separate (firewall licence ZS-CTP-1, Support Plus, browser isolation, AppProtection).
- **Idea:** Core (web), Access (ZTNA), Complete (everything). One page, no add-on matrix.

---

## 2. Onboarding and defaults

### 2.1 Safe-defaults policy pack ("Recommended policy")
- **Observation `[V]`:** the reference architectures are long (the ZIA forwarding guide has sections on fixed-site transparent forwarding, dedicated proxy ports, Client Connector, non-Zscaler source IP, proxy chaining), which suits an enterprise architect and not a ten-person firm.
- **Idea:** one-click policy pack: block known-bad categories, TLS inspection with a curated exemption list, block uploads to unsanctioned file sharing, require posture for sensitive apps. Zscaler already has the rule engine, so this is content.
- **Effort `[I]`:** low.

### 2.2 Forwarding chooser
- **Observation `[V]`:** the forwarding guide lists many methods and recommends Client Connector for roaming users.
- **Idea:** a three-question wizard (where are users, what devices, do you have a router that supports tunnels) that picks the method and generates the config or MDM payload. It encodes the guide's own recommendations.

### 2.3 Self-serve onboarding under 30 minutes
- **Idea:** connect IdP, send an install link by email or MDM, apply the default pack, show the first protected user on a dashboard. `[I]`: Zscaler's SMB programme is partner-led, so a self-serve path to the same bundle would let partners skip services work.

---

## 3. Operations for people without a security team

### 3.1 Plain-language alerts with one recommended action
- **Idea:** each alert says what happened, who is affected, and one button (block, isolate, ignore with reason). Cato's pitch to SMB is that the platform does the SecOps work `[I: COMPETITIVE-ANALYSIS.md]`. Zscaler has the telemetry already.

### 3.2 Weekly executive digest
- **Idea:** one email per week: threats blocked, shadow-SaaS found, devices out of posture, top three things to fix. Cheap: reporting data exists. Useful for the owner who is the "security team".

### 3.3 Cyber-insurance evidence export
- **Idea:** one-click PDF showing MFA enforcement, segmentation, logging and endpoint posture, mapped to common insurer questionnaire items. Insurance is a major reason small firms buy security `[I]`. This is a report template over existing data.

### 3.4 Free exposure scan as a lead and onboarding seed
- **Observation `[V]`:** Zscaler already offers an Internet Threat Exposure Analysis.
- **Idea:** surface it in the SMB signup flow and feed its findings into the default policy.

---

## 4. Private access (ZPA) gaps relative to SMB needs

### 4.1 "Replace my VPN" import
- **Observation `[V]`:** ZPA Private Service Edge and universal ZTNA material is written for sites with data centres and compliance needs.
- **Idea:** import firewall or VPN configs (subnets, ports, groups) and propose app segments automatically. Zscaler's autonomous segmentation add-on `[V]` points the same way, so extending it to a one-time migration is a natural step.

### 4.2 Connector in a box
- **Idea:** a prebuilt connector image for the common small-office targets (Synology/QNAP NAS, Raspberry Pi class devices, a single VM template, cloud marketplace one-click). Removes the "who installs the connector" blocker. `[I]`

### 4.3 Per-app share links for contractors
- **Observation `[V]`:** third-party access is a 500-user add-on.
- **Idea:** a time-boxed, single-app link for an outside accountant or contractor, expiring automatically, with logging. Clientless access exists; this is packaging and an invitation UX.

---

## 5. Endpoint agent (Client Connector)

### 5.1 Guest and BYOD mode
- **Observation `[V]`:** Palo Alto sells a secure browser for unmanaged devices (Prisma Access Browser). Zscaler has browser isolation as a paid add-on.
- **Idea:** bundle isolation or a managed-browser session as the default for contractors and personal devices in the SMB tier, with the traffic allowance pooled (Zscaler already pools 1.5 GB per user per month for Zero Trust Browser Advanced `[V: DS-ZIA]`).

### 5.2 Agent health that explains itself
- **Idea:** when the agent is bypassed, offline or in a captive portal, show the user and admin why, in plain terms, and give a fix action. Cheap UX work, and likely a top support-ticket category `[I]`.

---

## 6. Competitive and positioning moves

### 6.1 MSP multi-tenant console
- **Observation `[I]`:** Cato's strength with small firms is managed-service delivery.
- **Idea:** a single-pane, multi-tenant MSP view with per-client billing and policy templates. Zscaler's partner-led SMB push needs this to scale.

### 6.2 Migration offers from Cato and Palo Alto
- **Idea:** importers and a comparison table for customers leaving other SASE or VPN products. Marketing plus a config converter.

### 6.3 AI-usage visibility as an SMB hook
- **Idea:** an out-of-the-box "which AI tools are my staff using, and what are they pasting" report with a one-click block or warn. Reuses existing SaaS and DLP inspection. Timely, and visible to owners. `[I]`

---

## Suggested first three

| # | Idea | Why first |
|---|---|---|
| 1 | 1.1 No-minimum SMB bundle + 1.2 public prices | Biggest barrier is commercial, and costs no engineering |
| 2 | 2.1 Safe-defaults pack + 3.1/3.2 plain-language alerts and digest | Turns existing features into value for a firm with no security staff |
| 3 | 3.3 Insurance evidence export | Report template, concrete buying trigger |

## Caveats

- I read the Zscaler sheets selectively (data sheets for ZIA, ZPA, firewall, bandwidth, Client Connector, PSE; the forwarding and NIST guides were skimmed). Treat section 2.2 and 4.x as hypotheses to confirm against the full guides.
- Zscaler may already ship parts of these (for example SMB bundles or evidence reports). Check the current product before proposing.
