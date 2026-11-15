# Competitive analysis: Cato Networks and Palo Alto Networks (Prisma SASE)

**Purpose:** pick ideas for the small-business zero trust product (see `REQUIREMENTS.md`) from two Zscaler competitors.
**Date:** 2026-11-15. **Status:** draft v0.1.
**Local copies of the PDFs:** `.doc/` (git-ignored, not published).

Tags: `[V]` = read in a source named in section 5. `[I]` = inferred or marketing, check before relying on it.

---

## 1. Research limits (read first)

- **Cato.** No official `catonetworks.com` data sheet PDF turned up. The PDFs read are a **Cato-branded solution brief hosted by a reseller** (`cato-solution-brief-zift.pdf`, undated, and it names SSE 360, XDR, DEM, EPP and IoT/OT, so it is recent), two reseller overviews, and the "SASE for Dummies, Cato edition" book (only grepped, not read in full). The "Single Pass Cloud Engine" white paper is behind a form and was **not** read. Two Cato web pages were read in a browser: the platform architecture page and the "What Is Cato Private Access?" knowledge-base article.
- **Palo Alto Networks.** The official Prisma Access spec sheet page rendered no content. PDFs read: Prisma SASE data sheet (April 2024), Prisma Access data sheet (**February 2020**, old), "10 Tenets of an Effective SASE Solution" (2022), Prisma Access Browser white paper (2025), and a zero-trust deck (2021). The CIO guide to SASE was downloaded but **not read**. One blog post was read through a fetch tool.
- **Patents.** Justia and Google Patents search were blocked or unhelpful for Cato. I read **one** Cato patent *application* (pending, claims not read) and **one** Palo Alto patent (US 12,003,485 B2, claims not read, only the description). Neither is a freedom-to-operate review. Patent counsel should review before any design is copied.
- **Pricing.** No Cato pricing was found. Palo Alto's pricing is only visible as minimums in the old 2020 data sheet.
- Most figures below are vendor marketing. Three vendors each claim to be the leader.

---

## 2. Cato Networks

### 2.1 Approach

Cato calls itself the first single-vendor SASE. It converges SD-WAN and security into one cloud service that runs over its **own private backbone** of points of presence (PoPs), connected by "multiple tier-1 carriers" with "no hyperscaler dependency" `[V: architecture page]`. Zscaler, by contrast, sells the security edge and leaves the network to the customer.

| Cato element | What it is | Source |
|---|---|---|
| **SPACE** (Single Pass Cloud Engine) | Decrypts once and applies NGFW, SWG, IPS, anti-malware, RBI, CASB, DLP and ZTNA in one pass. Runs as software on bare metal in every PoP | architecture page `[V]` |
| **Single policy engine** | NGFW, CASB, DLP, ZTNA, threat prevention and AI controls share one rule base, so "one policy definition" applies everywhere | architecture page `[V]` |
| **Open data lake** | Every inspected flow's network, device, user, app and data context, plus hundreds of third-party feeds, queryable through the API | architecture page `[V]` |
| **Socket** | Zero-touch edge SD-WAN device. Active/active links, per-app dynamic path selection, packet-loss mitigation by duplicating packets per application, BGP, HA with "no additional recurring charge" | solution brief `[V]` |
| **vSocket / agentless cloud** | Cloud datacentres join through redundant IPsec tunnels with no virtual appliance, which Cato says avoids AWS Direct Connect or Azure ExpressRoute | solution brief `[V]` |
| **Smart egress** | Application-level rule that exits specific app traffic at the PoP nearest the target instance | solution brief `[V]` |
| **Managed services** | Self-service, **co-managed**, or **fully managed** by a partner. Managed XDR by the Cato SOC. A named Customer Success Engineer | solution brief `[V]` |
| **XDR** | AI-built "stories" from native flow data, UEBA, guided investigation, playbooks | solution brief `[V]` |
| **DEM** | Real-user and synthetic probes, hop-by-hop view, 10,000+ apps, 3 months of history | solution brief `[V]` |
| **IoT/OT** | Fingerprinting by ML, policy by device group, same threat prevention | solution brief `[V]` |
| **EPP** | Endpoint protection in the same console, with a SentinelOne ML engine for unknown malware | solution brief `[V]` |
| **Compliance** | PCI 4.0, SOC 1 and 2, ISO 27001/27017/27701/27018, GDPR. Inspected data "never stored". Privacy-sensitive apps (banking, healthcare) can be excluded from inspection | solution brief `[V]` |
| **Claims** | 99.999% availability, 80+ PoPs, 150+ countries (the brief also says "8 +" in places, a typo) | solution brief `[V: marketing]` |

### 2.2 Cato Private Access (their ZTNA)

From the knowledge-base article `[V]`:

- Brokered, user-to-application access, no network extension. **User-initiated only**: server-initiated and bidirectional flows are not supported and need the full Socket/IPsec networking.
- Flow: user connects with the client or clientless, the PoP authenticates and evaluates policy, an **outbound DTLS tunnel** runs from an **App Connector** to the PoP, and the connector forwards only authorised sessions.
- **App Connector Groups** give high availability and load distribution. Applications attach to a **group**, not to one connector.
- **Default-deny** policy, evaluated at the PoP before any session reaches the application environment.
- **Overlapping-IP / M&A support:** apps are abstracted from internal addressing with **CGNAT ranges (default 100.64.0.0/16 for management and 100.65.0.0/16 for applications) and DNS mapping**. No re-addressing and no site on-ramping.

### 2.3 Patent signal

- **US 2026/0186764 A1**, "Cloud service selectively switches tunnels for smooth maintenance" (pending, published 2026-07-02, priority 2024-12-31, five named inventors). The description: the service tracks upgrade schedules and tunnels, picks an alternative server, and **reroutes client traffic before an upgrade starts**, so upgrades do not break connections `[V: description only, claims not read]`. Cato holds 18 documents, 3 granted and 14 pending, per a PitchBook summary `[I: secondary source]`.

### 2.4 Company context

Tel Aviv. Co-founded by Shlomo Kramer and Gur Shatz `[V: search results]`. Latest confirmed valuation above $4.8B (2025 Series G), about $1B+ raised `[I: sources disagree on exact figures]`.

---

## 3. Palo Alto Networks (Prisma SASE)

### 3.1 Approach

Prisma SASE bundles **Prisma Access** (security: SWG, FWaaS, ZTNA, CASB, DLP), **Prisma SD-WAN**, **Prisma Access Browser**, and **ADEM** (digital experience), managed from one console on one data lake `[V: Prisma SASE data sheet 2024]`. Its zero trust story is branded **ZTNA 2.0**.

| PAN element | What it is | Source |
|---|---|---|
| **ZTNA 2.0** | "Fine-grained, least-privileged access with behavior-based continuous trust verification and deep, ongoing security inspection and enterprise DLP" | Prisma SASE sheet `[V]` |
| **App-ID, User-ID, Device-ID** | Identification of the application (and sub-application), the user and the device, used in every rule | Prisma SASE sheet `[V]` |
| **Continuous trust assessment** | Dynamic user-group monitoring "before the IdP or identity store is updated", posture, location and session changes feed risk, **policy-based MFA step-up** by app sensitivity, enforcement at the **first packet**, supervised and unsupervised ML inline and out-of-band | PAN blog `[V]` |
| **Credential theft prevention** | Blocks untrusted sites and scans credentials as typed against corporate credentials | PAN blog `[V]` |
| **Single-pass inspection** | Layer 3–7 inspection of all traffic including private apps, with WildFire sandbox analysis | PAN blog `[V]` |
| **Explicit proxy** | Lets customers migrate from a legacy proxy with no network change | Prisma SASE sheet `[V]` |
| **SSPM** | Continuous check of SaaS configuration against best practice | Prisma SASE sheet `[V]` |
| **AIOps** | Anomaly detection and forecasting, automated troubleshooting, **change-management modelling**, security policy analysis | Prisma SASE sheet `[V]` |
| **Prisma Access Browser** | Secure enterprise browser for managed and unmanaged devices, "to any device in minutes" (see 3.2) | white paper `[V]` |
| **Clean Pipe** | Multi-tenant offering for service providers and telcos | 2020 data sheet `[V]` |
| **Locations / SLA** | 140+ locations in 87 countries. Uptime 99.999% per calendar month. Connectivity 99.99% for 10 ms over a 1-hour period | Prisma SASE sheet `[V: marketing]` |
| **Agent** | GlobalProtect: always-on, pre-logon, on-demand, split tunnel by route, per-app and by low-risk app | 2020 data sheet `[V]` |

### 3.2 Prisma Access Browser (strongest SMB idea)

From the white paper (2025) `[V]`: PAN says employees spend over 85% of the day in a browser and about 95% of organisations report browser-based threats (vendor/Omdia research, not independently verified). The browser is meant to give a **secure workspace on unmanaged and BYOD devices** with no MDM, including:

- **Last-mile data controls:** screenshot, camera and microphone blocking, data masking, watermarking, file encryption.
- **Last-mile access controls:** login restrictions, MFA, privileged-access management, admin approval.
- **Browser hardening:** defence against malicious extensions and keyloggers, disabling sensitive browser components, **device posture re-checked every 90 seconds**, an extra encryption layer, web insights for forensics.
- Inspection of traffic that proxies miss (QUIC, ECH), and "no proxy, lower cost".

### 3.3 Patent signal

- **US 12,003,485 B2**, "Outbound/inbound lateral traffic punting based on process risk" (granted 2024-06-04, priority 2017-09-15, Google's estimated expiry 2037, claims not read) `[V: description only]`. An endpoint agent maps each socket to a **process hash**, applies a whitelist/blacklist of process digests, and **punts risky-process traffic over a tunnel to a firewall or cloud service**. The network side correlates **App-ID with process ID** for fine-grained policy and can block, throttle, alert or **tell the agent to kill the process**. Zscaler's "Endpoint App Control" (data sheet DS-FW) is a similar idea.

### 3.4 Packaging (old, from the 2020 data sheet)

- Prisma Access for Users: licensed per unique user, **minimum 200 users**. Prisma Access for Networks: bandwidth pool, **minimum 200 Mbps** `[V: 2020]`.
- Included: URL filtering, threat prevention, WildFire, host information profile, DNS security. **Separate subscriptions:** DLP, Cortex XDR, Prisma SaaS, AutoFocus. **Cortex Data Lake is required for logging and is a paid subscription** `[V: 2020, may have changed]`.

---

## 4. Side by side (the three vendors)

| Topic | Zscaler | Cato | Palo Alto |
|---|---|---|---|
| Model | Security cloud, network is yours | Converged network + security, own backbone | Converged, built on firewall heritage |
| Policy | Several policy modules with an evaluation order | **One rule base, one engine** | One policy model with App/User/Device-ID |
| Private access | Brokered, App Connector, stitching, AI segmentation | Brokered, App Connector Groups, outbound DTLS, CGNAT abstraction | ZTNA 2.0: app and sub-app, continuous trust, deep inspection |
| Unmanaged devices | Browser access, isolation | Clientless, RBI | **Full secure browser** |
| Managed service | Professional services | **Co-managed, fully managed, managed XDR** | Partner-led |
| Seat or size minimum | 500-user minimums on many items | Not found | 200 users (2020 sheet) |
| Availability claim | 99.999% by transactions lost | 99.999% | 99.999% per month |
| Logging cost | Included, 6 months | Not found | Cortex Data Lake, paid |

**Reading:** none of the three publishes a small-business price or a self-serve path in the material read. All three have 200–500 user minimums or are quote-based `[V where stated, else I]`. That supports the SMB-006 requirement (no seat minimums).

---

## 5. Sources

Read in a browser or from PDFs (local copies in `.doc/`):

- Cato, Platform Architecture: https://www.catonetworks.com/platform/architecture/
- Cato, What Is Cato Private Access?: https://knowledge.catonetworks.com/docs/what-is-cato-private-access
- Cato SASE Cloud Platform solution brief (reseller-hosted): `.doc/cato/cato-solution-brief-zift.pdf`
- Cato reseller overviews: `.doc/cato/bcn-sse360-overview.pdf`, `.doc/cato/bcn-solution-brief.pdf` (skimmed only)
- SASE for Dummies, Cato Networks Special Edition: `.doc/cato/sase-for-dummies-cato.pdf` (grepped only)
- Cato patent application US 2026/0186764 A1: https://patents.google.com/patent/US20260186764A1/en
- Palo Alto, Prisma SASE data sheet (April 2024): `.doc/paloalto/prisma-sase-carahsoft.pdf`
- Palo Alto, Prisma Access data sheet (Feb 2020): `.doc/paloalto/prisma-access-ds-old.pdf`
- Palo Alto, 10 Tenets of an Effective SASE Solution (2022): `.doc/paloalto/10-tenets-sase.pdf`
- Palo Alto, Prisma Access Browser white paper (2025): `.doc/paloalto/prisma-access-browser.pdf`
- Palo Alto, Complete Zero Trust Network Security deck (2021): `.doc/paloalto/zero-trust-westcon.pdf` (skimmed)
- Palo Alto blog, The ZTNA superpowers in Prisma Access: https://www2.paloaltonetworks.com/blog/sase/the-ztna-superpowers-in-prisma-access.md
- Palo Alto patent US 12,003,485 B2: https://patents.google.com/patent/US12003485B2/en

Downloaded and **not read:** `.doc/paloalto/cio-guide-sase.pdf`.
Not obtained: Cato's SPACE white paper (gated), Palo Alto's current Prisma Access spec sheet (page did not render).
