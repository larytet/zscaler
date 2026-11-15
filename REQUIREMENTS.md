# Requirements Specification: Small-Business Zero Trust Platform

**Working name:** SMB-ZTX (placeholder)
**Goal:** Feature parity with the Zscaler Zero Trust Exchange (ZIA, ZPA, ZDX, data security) for organisations of roughly 5–250 people with no dedicated security team.
**Status:** Draft v0.1, 2026-11-15
**Audience:** Product, architecture, engineering

---

## 0. How to read this document

- Requirement IDs are stable (`ZIA-…`, `ZPA-…`). Priority is **M** (must, needed for parity), **S** (should), **C** (could).
- Each section has a **Parity source** line. Sources are listed in section 14. Nothing in this document comes from a Zscaler contract, a customer NDA or non-public material.
- **Confidence markers:** `[V]` means verified against a Zscaler page or patent read for this document. `[I]` means inferred from public descriptions or general industry practice, and must be checked before it is committed to a roadmap.
- "Parity" here means functional parity at the capability level. It does not mean copying Zscaler's implementation, and it does not mean equal global scale (see section 3, non-goals, and section 13).

### 0.1 Research limits (read first)

- The Zscaler help portal (`help.zscaler.com`) renders client-side and several guessed URLs returned 404. Only the pages listed in section 14 were read. The ZIA module list in section 6 is therefore partly `[I]`.
- Patents were read via Google Patents text (truncated at about 100k characters each). Claim language was **not** read. Patent references below are used to understand architecture only. **This spec is not a freedom-to-operate analysis.** Zscaler holds patents on connector stitching, session-key snooping and related designs. Get patent counsel review before building the designs in section 5.4 and 6.4.
- No pricing was found. Zscaler's SMB announcement (2026-08-18, with Carahsoft) says "predictable, right-sized" pricing but gives no figures or seat minimums `[V]`.

---

## 1. Product vision and target customer

### 1.1 Problem

Small businesses face the same ransomware, phishing and identity-based attacks as large enterprises, but lack a security team, a network team and enterprise budgets. Zscaler itself says SMB security teams "often lack the resources to confront these threats at scale" `[V: Carahsoft press release]`. Legacy answers (VPN appliances, branch firewalls) are exposed to the internet and grant network-level access, which allows lateral movement. Zscaler cites that 54% of VPN-related breaches involve lateral movement `[V: ZPA product page]` (a vendor figure, not independently verified).

### 1.2 Target customers (personas)

| Persona | Description | Key need |
|---|---|---|
| P1 Owner/operator | 5–25 staff, one person does IT part time | Works out of the box, no policy authoring |
| P2 Small engineering team | 10–50 engineers, cloud + SaaS, some contractors | Safe access to staging/prod, coding tools, no VPN |
| P3 MSP/reseller admin | Manages 20–500 small tenants | Multi-tenant console, templates, billing |
| P4 Compliance-driven SMB | Healthcare, finance, legal, 25–250 staff | Evidence, logs, data residency, DLP |

### 1.3 Design principles

1. **Secure by default, zero configuration to first value.** The default policy must be safe and require no authoring.
2. **Recommend, don't require.** Zscaler's own ZPA uses AI-generated segment and policy recommendations `[V]`. For SMB this must be the primary path, not an advanced option.
3. **Never place the user on the network.** Access is user-to-application, brokered, with applications not reachable from the internet `[V]`.
4. **One agent, one console, one bill.**
5. **Operable by a non-expert in under 30 minutes per week.**

---

## 2. Scope

### 2.1 In scope (parity set)

1. Secure web and SaaS access (the ZIA equivalent): proxy, TLS inspection, URL/app control, threat protection, data protection.
2. Private application access (the ZPA equivalent): ZTNA, segmentation, browser access, privileged remote access.
3. Endpoint agent (the Client Connector equivalent) with device posture.
4. Digital experience monitoring (the ZDX equivalent).
5. Cloud/workload and branch connectivity (reduced scope, see 8).
6. Logging, reporting, SIEM export, APIs.
7. Multi-tenant administration and MSP operation.

### 2.2 Non-goals for v1

- Matching Zscaler's 200+ public data centre footprint `[V: press release says 200+]`. Use fewer PoPs via partner clouds.
- IoT/OT segmentation beyond basic agentless connector access.
- Deception, Zscaler-style ITDR and CTEM modules (revisit in v2).
- On-premises virtual appliances for the policy engine. (Zscaler allows PE/PEP to run locally in virtualised form `[V: NIST white paper]`. Defer.)
- Government accreditation (FedRAMP, DoD) in v1.

---

## 3. Reference architecture

Parity source: NIST white paper `[V]`, ZPA product page `[V]`, patents US 11,750,405 and US 11,652,797 `[V]`.

### 3.1 Logical components (NIST SP 800-207 mapping)

| NIST component | Zscaler realisation `[V]` | SMB-ZTX requirement |
|---|---|---|
| Policy Engine (PE) | Cloud-hosted central authority and policy engines | ARCH-001 |
| Policy Administrator (PA) | Broker / central authority issuing tokens and connection info | ARCH-002 |
| Policy Enforcement Point (PEP) | Enforcement nodes (ZIA), Service Edge (ZPA) | ARCH-003 |
| Data sources | IdP, SIEM, PKI, EDR/compliance integrations direct; CDM and threat intel indirect | ARCH-004 |

- **ARCH-001 (M):** A multi-tenant central authority stores tenant policy and configuration, distributes threat updates, and pushes policy to enforcement nodes, which cache it and hold persistent connections to the authority `[V: US 11,750,405]`.
- **ARCH-002 (M):** Control plane and data plane are independent, so a control-plane outage does not drop established sessions, and no customer traffic flows through policy engines `[V]`.
- **ARCH-003 (M):** Enforcement nodes run active-active, hold traffic in memory and do not write customer payloads to disk `[V: US 11,750,405]`.
- **ARCH-004 (M):** Direct integrations with IdP (SAML/OIDC, SCIM), SIEM, and endpoint-compliance sources.
- **ARCH-005 (M):** Policy follows the user, not the network location `[V]`.
- **ARCH-006 (M):** Criteria-based trust evaluation (identity, device posture, location, risk score) per request `[V: "criteria-based trust algorithms"]`.
- **ARCH-007 (S):** Dynamic risk scoring and "active defense" feeding policy decisions `[V: named in NIST white paper; mechanics not described]`.
- **ARCH-008 (M):** The system must be designed against the NIST-named risks: subversion of the decision process, denial of service, insider threat, loss of network visibility, storage of metadata and policies `[V]`.

### 3.2 NIST deployment models to support

- **ARCH-010 (M):** Device agent/gateway-based model (the agent).
- **ARCH-011 (M):** Resource-portal model (clientless browser access).
- **ARCH-012 (S):** Enclave-based model (connector in front of a group of resources).
- **ARCH-013 (C):** Software-defined perimeter semantics as an option for sensitive apps.

### 3.3 NIST use cases to demonstrate

Enterprise with satellite facilities; multi-cloud; contracted services and non-employee access; collaboration across enterprise boundaries (B2B); public or customer-facing services `[V]`. For SMB, the required ones are: remote workforce, multi-cloud engineers, contractor access, and partner/B2B access.

### 3.4 Tenancy and isolation

- **ARCH-020 (M):** Strong logical tenant isolation for policy, logs and keys.
- **ARCH-021 (M):** Per-tenant TLS interception CA, never shared across tenants.
- **ARCH-022 (S):** Tenant-selectable data residency for logs and inspection (see DATA-SOV).

---

## 4. Endpoint agent (Client Connector equivalent)

Parity source: ZPA/ZIA pages, NIST paper, patents `[V]` unless marked.

- **AGT-001 (M):** Single lightweight agent for Windows, macOS, Linux, iOS, Android, ChromeOS `[I]` (platform list not confirmed from pages read).
- **AGT-002 (M):** Forwards web traffic to the nearest cloud node and private-app traffic to the broker. Connects outbound only and accepts no inbound connections `[V: US 11,652,797]`.
- **AGT-003 (M):** SSO sign-in through the tenant IdP `[V]`.
- **AGT-004 (M):** Always-on with tamper protection and admin-controlled disable/uninstall passcodes `[I]`.
- **AGT-005 (M):** Device posture collection: OS version, disk encryption, firewall, EDR running, certificate present, domain/MDM enrolment `[V: "device posture profiles" exist; the criteria list is `[I]`]`.
- **AGT-006 (M):** Trusted-network detection that adjusts forwarding when the user is on a corporate network `[V: "trusted networks" criterion]`.
- **AGT-007 (M):** Forwarding profiles, PAC and tunnel modes, with bypass lists `[I]`.
- **AGT-008 (S):** Fail-open and fail-closed settings per tenant and per app, plus captive-portal handling `[I]`.
- **AGT-009 (S):** Silent deployment through MDM (Intune, Jamf, Google Workspace) and scripts, plus a one-click "invite user by email" flow for P1.
- **AGT-010 (S):** Agent-embedded digital experience probes (see 9).
- **AGT-011 (M):** Agent performance budget: under 3% sustained CPU and under 200 MB RSS on a reference laptop `[I: engineering target, not a Zscaler figure]`.

---

## 5. Private access (ZPA equivalent)

Parity source: ZPA product page, About Access Policy help page, US 11,652,797, leading practices search results `[V]`.

### 5.1 Core model

- **ZPA-001 (M):** Brokered one-to-one connections between an authorised user and a specific application. The user is never placed on the corporate network and applications are never exposed to the public internet `[V]`.
- **ZPA-002 (M):** Applications are "dark": no inbound listeners on the customer side `[V: US 11,652,797]`.
- **ZPA-003 (M):** Replace a VPN "in hours" for a typical SMB. Target: first app reachable within 30 minutes of sign-up `[V: Zscaler claims "in just hours"; the 30-minute target is ours]`.

### 5.2 App connector

- **ZPA-010 (M):** Lightweight connector deployable as a container, VM image, Linux package or ephemeral binary, making outbound-only connections `[V]`.
- **ZPA-011 (M):** Connector groups, HA pairs and automatic failover `[I]`.
- **ZPA-012 (M):** Connector can answer discovery queries (for example wildcard domain lookups) to enumerate applications behind it `[V: US 11,652,797]`.
- **ZPA-013 (S):** Connector auto-update with maintenance windows `[I]`.
- **ZPA-014 (S):** One-command deployment for AWS, Azure, GCP and Kubernetes `[I]`.

### 5.3 Application segmentation and policy

- **ZPA-020 (M):** Application segments (hosts, ports, protocols), segment groups and server groups `[V: segment and segment-group terms]`.
- **ZPA-021 (M):** **AI/heuristic app discovery** and segment/policy recommendations `[V: "AI-Powered App Segmentation"]`. Required to be the default onboarding path. Zscaler's leading practices suggest a time-limited "discovered applications" rule (for example 60 or 90 days) before moving to granular segments `[V: search result summary]`. SMB-ZTX should automate that transition.
- **ZPA-022 (M):** Access policy rules with action **Allow**, **Block**, **Require Approval** `[V]`.
- **ZPA-023 (M):** Rule criteria: users/groups, SAML and SCIM attributes, device posture profiles, trusted networks, client types, machine groups, connector-group criteria `[V]`.
- **ZPA-024 (M):** Top-down, first-match evaluation using the most specific application segment, with explicit rule order `[V]`.
- **ZPA-025 (M):** Boolean operators between criteria, with behaviour documented unambiguously. (Zscaler's own pages differ on OR/AND defaults for posture sets, so SMB-ZTX must pick one and test it.)
- **ZPA-026 (M):** Rule copy, usage view and per-rule hit counts `[V: copy and "policy usage details" exist]`.
- **ZPA-027 (S):** Time-based access and just-in-time access with an approval workflow, via Slack/Teams/email approver `[V: "Require Approval" exists; the workflow is `[I]`]`.
- **ZPA-028 (S):** Policy simulation: show who would lose access before a change is applied `[I]`.
- **ZPA-029 (M):** Additional policy types beyond access: timeout, client forwarding, and inspection policies `[I: names from general product knowledge]`.

### 5.4 Connection stitching

- **ZPA-030 (M):** The user-side node and the connector-side node each connect outbound, and the cloud joins them. Tokens from the central authority authorise each side `[V: US 11,652,797]`.
- **ZPA-031 (M):** End-to-end encryption using client-side and server-side certificates, so that broker nodes do not take part in the key exchange `[V: US 11,652,797]`. Note this conflicts with inline inspection of private traffic. See ZPA-041.
- **ZPA-032 (M):** Access decisions check both user and device policy before stitching `[V]`.
- **ZPA-033 (M):** Connect to the closest node at agent start, with automatic re-selection on failure `[V]`.

### 5.5 Access types

- **ZPA-040 (M):** **Browser access** (clientless) for web apps, RDP, SSH, with no agent, for unmanaged devices and contractors `[V]`.
- **ZPA-041 (S):** **Inline inspection of private app traffic** (AppProtection-style) with DLP `[V: "full inline inspection of private app traffic and DLP"; the AppProtection policy page exists]`. Requires an opt-in per segment because it needs the key-exchange design in ZPA-031 to be relaxed.
- **ZPA-042 (M):** **Privileged remote access**: clientless RDP, SSH, VNC to production systems for staff and third parties, with session recording `[V: capability named; recording is `[I]`]`.
- **ZPA-043 (S):** **Private service edge**: on-premises broker so in-office users reach local apps without a cloud hairpin `[V]`.
- **ZPA-044 (S):** **Business continuity**: policy-enforced access during outages of the broker, via a local cached mode `[V: capability named]`.
- **ZPA-045 (S):** **Extranet/partner app access** to apps in a partner's network without network merging `[V]`.
- **ZPA-046 (M):** **B2B federation:** a guest partner admin creates rules for shared access to the host tenant's applications `[V: help page]`.
- **ZPA-047 (C):** Workload-to-workload segmentation across clouds `[V]`.
- **ZPA-048 (C):** OT/IoT remote maintenance access `[V]`.
- **ZPA-049 (C):** Deception-based access policies `[V: noted on help page]`.

---

## 6. Secure internet and SaaS access (ZIA equivalent)

Parity source: ZIA product page `[V]`, patent US 11,750,405 `[V]`, policy-order search results `[V]`, module names `[I]` unless noted.

### 6.1 Proxy and gateway

- **ZIA-001 (M):** Cloud forward proxy (secure web gateway) with a full proxy architecture `[V]`.
- **ZIA-002 (M):** Inspect **100% of TLS/SSL traffic** at scale `[V: Zscaler claim]`. Target: inspection on by default with a managed exemption list.
- **ZIA-003 (M):** Direct-to-cloud local breakout, no backhaul `[V]`.
- **ZIA-004 (M):** Policy follows the user across devices and networks `[V]`.
- **ZIA-005 (M):** Cloud firewall for non-web outbound traffic (DNS, SSH, other ports) `[V: leading practices summary]`.
- **ZIA-006 (S):** Egress NAT with static IPs for allow-listing by SaaS vendors `[V: "Egress NAT" named]`.

### 6.2 Policy framework and evaluation order

Evaluation order from Zscaler's ZIA policy leading practices `[V: search summary]`:

1. Firewall
2. SSL inspection
3. Advanced threat protection
4. Malware/antivirus
5. Cloud app control
6. URL control
7. File type control
8. DLP
9. Cloud sandbox

- **ZIA-010 (M):** Reproduce this layered order, with a firewall block overriding a web allow `[V]`.
- **ZIA-011 (M):** Cloud App Control: allow/block by application and by action (upload, post, share). An explicit allow skips URL filtering unless "cascade to URL filtering" is on. A block always wins `[V]`.
- **ZIA-012 (M):** URL filtering as the default access control, with category, custom category and per-user/group/location rules `[V]`.
- **ZIA-013 (M):** File type control `[V]`.
- **ZIA-014 (M):** Policy reason strings visible in logs and block pages, so admins and users know why a request was denied `[V: "Policy Reasons" page exists]`.
- **ZIA-015 (S):** Recommended baseline URL and Cloud App Control policy as a one-click template `[V: Zscaler publishes one]`.
- **ZIA-016 (M):** Bandwidth control, time quotas and browser/user-agent control `[I]`.

### 6.3 Threat protection

- **ZIA-020 (M):** Malware and antivirus scanning inline `[V]`.
- **ZIA-021 (M):** Advanced threat protection: phishing, botnet/C2 callbacks, malicious active content, cryptomining `[I]`.
- **ZIA-022 (M):** Intrusion prevention and DNS security (filtering, DNS tunnelling detection) `[I]`.
- **ZIA-023 (M):** Cloud sandbox for unknown files with AI-driven instant verdicts, and large-file sandboxing `[V: product page mentions "sandboxing code and unknown or large files with instant AI-verdicts"]`.
- **ZIA-024 (S):** Browser isolation for risky or uncategorised sites `[V: search result mentions a file isolated on a remote browser]`.
- **ZIA-025 (S):** Threat intelligence feed updates pushed to enforcement nodes in near real time `[V: central authority distributes threat updates]`.

### 6.4 TLS inspection design

Parity source: US 11,750,405 `[V]`.

- **ZIA-030 (M):** Man-in-the-middle interception proxy that terminates and re-establishes TLS, using a per-tenant CA `[V]`.
- **ZIA-031 (S):** Alternative **handshake-snooping** mode for apps with certificate pinning, which derives keys from the observed handshake and inspects traffic without breaking the tunnel `[V: patent description]`. **Patent risk: high. Needs counsel.**
- **ZIA-032 (M):** Automatic exemption lists for pinned apps, banking and health categories, with admin override `[I]`.
- **ZIA-033 (M):** Automated trust of the tenant CA on managed devices (MDM profile, agent-installed) `[I]`.
- **ZIA-034 (S):** Automated inspection coverage for 30+ developer tools (git, package managers, container registries, CLIs), which otherwise break on custom CAs `[V: product page mentions 30+ dev tools]`.

### 6.5 Data protection

- **DATA-001 (M):** Inline DLP with built-in dictionaries (PII, PCI, health, credentials/secrets) and custom patterns `[V: DLP in module order; dictionaries `[I]`]`. DLP violations are reported as compliance events `[V]`.
- **DATA-002 (M):** SaaS posture and data scanning (CASB, API-based): shared-file exposure, risky OAuth grants, misconfigurations in Microsoft 365, Google Workspace, Slack, GitHub `[I]`.
- **DATA-003 (S):** Cloud (IaaS) posture checks `[I]`.
- **DATA-004 (M):** Generative AI controls: block or allow AI apps by category, real-time inspection of prompts (Zscaler cites Microsoft Copilot inspection) `[V]`.
- **DATA-005 (S):** Endpoint DLP and USB/removable media control through the agent `[I]`.
- **DATA-006 (S):** Email DLP and exact data match / index document match `[I]`.
- **DATA-SOV (S):** Data and content sovereignty: egress NAT, geolocalised content, in-country logging `[V: three features named on product page]`.

---

## 7. AI and developer-workflow security (differentiator, not strict parity)

Zscaler is positioning for the AI era (ZIA mentions Copilot prompt inspection and dev-tool inspection) `[V]`. For P2 customers the following are strongly recommended:

- **AI-001 (S):** Per-tool allow lists for AI coding assistants and agents, identity-bound to the human operator.
- **AI-002 (S):** Agent-to-resource access through the same broker as human access: scoped, short-lived, logged `[I]`.
- **AI-003 (S):** Prompt and response DLP for sanctioned AI tools.
- **AI-004 (C):** Per-agent audit trail linking prompts, tool calls, and network access.

---

## 8. Branch, cloud and workload connectivity (reduced scope)

- **BR-001 (S):** Site-to-cloud connector (small virtual appliance or router config) for offices with unmanaged devices, using GRE/IPsec `[I]`.
- **BR-002 (S):** Guest Wi-Fi and IoT segments forwarded to the cloud with a restricted policy `[I]`.
- **BR-003 (C):** Cloud workload egress protection for AWS, Azure and GCP VPCs `[V: Zscaler offers workload segmentation; implementation `[I]`]`.
- **BR-004 (C):** Cloud-to-cloud and app-to-app communication configuration `[V: NIST paper]`.

---

## 9. Digital experience monitoring (ZDX equivalent)

Parity source: product page lists "Digital Experience Monitoring" `[V]`. Details `[I]`.

- **DEX-001 (S):** Per-user and per-app experience score from agent probes (web, network path, device health).
- **DEX-002 (S):** Hop-by-hop path analysis from device to app, separating device, Wi-Fi, ISP, cloud and app causes.
- **DEX-003 (S):** Device health: CPU, memory, disk, Wi-Fi signal.
- **DEX-004 (C):** Synthetic probes of SaaS and private apps from connectors.
- **DEX-005 (C):** AI-assisted root-cause summary suitable for a non-expert admin.

---

## 10. Identity and integrations

- **INT-001 (M):** SAML 2.0 and OIDC SSO with Microsoft Entra ID, Google Workspace, Okta, JumpCloud `[I]`.
- **INT-002 (M):** SCIM provisioning of users and groups `[V: SCIM attributes in policy]`.
- **INT-003 (M):** Device compliance signals from Intune, Jamf, Google endpoint management, CrowdStrike, SentinelOne, Microsoft Defender `[V: a Defender deployment guide exists]`.
- **INT-004 (M):** SIEM/log streaming (syslog, HTTPS, S3/Blob) with a documented schema `[V: SIEM integration]`.
- **INT-005 (S):** SOAR/XDR integrations and MITRE ATT&CK mapping of detections `[V: product page cites full MITRE ATT&CK mapping]`.
- **INT-006 (M):** Public REST API and Terraform provider covering every console action `[V: "API-first integrations" and RBAC]`.
- **INT-007 (S):** Slack/Teams notifications and approvals.

---

## 11. Administration, logging and reporting

- **ADM-001 (M):** Web console with a **simple mode** (three screens: users, apps, alerts) and an **advanced mode** exposing the full policy framework. This is the key SMB differentiator.
- **ADM-002 (M):** Role-based access control with at least: owner, admin, read-only, helpdesk, auditor `[V: RBAC]`.
- **ADM-003 (M):** Admin SSO with mandatory MFA, and an audit trail of every admin action `[I]`.
- **ADM-004 (M):** Policy change history, diff and rollback `[I]`.
- **ADM-005 (M):** Logging: web, firewall, DNS, private-access, admin and agent logs. Logs are compressed, tokenised and sent over TLS to regional log routers and a regional store `[V: US 11,750,405]`.
- **ADM-006 (M):** Real-time log search and dashboards with a default 30-day retention. Tenant-selectable longer retention `[I]`.
- **ADM-007 (M):** "Forensically complete" logging of every transaction `[V: product page claim]`, with a documented field list.
- **ADM-008 (S):** Scheduled reports (executive, compliance) as PDF/email.
- **ADM-009 (S):** Weekly "security digest" for P1 users in plain language.
- **ADM-010 (M):** **MSP console:** multi-tenant parent/child hierarchy, policy templates, cross-tenant dashboards, delegated admin, white-label branding, usage-based billing export `[I]`.

---

## 12. Non-functional requirements

All figures are engineering targets set for this document, unless marked `[V]`.

### 12.1 Performance

- **NFR-001 (M):** Added latency for web traffic under 20 ms at p50 and under 60 ms at p95, within a region that has a PoP.
- **NFR-002 (M):** Private-app connection set-up under 500 ms at p95 after the first session.
- **NFR-003 (M):** Throughput per user of at least 100 Mbps with TLS inspection on.
- **NFR-004 (S):** Policy propagation to all nodes in under 60 seconds.

### 12.2 Availability and resilience

- **NFR-010 (M):** Data-plane availability of 99.99% monthly `[I]`. Zscaler publishes its own SLAs, which were not read.
- **NFR-011 (M):** No single node, PoP, or control-plane failure drops established sessions `[V: control/data plane independence]`.
- **NFR-012 (M):** Deterministic fail-open or fail-closed behaviour per tenant, documented and testable.

### 12.3 Security of the platform itself

- **NFR-020 (M):** Customer payloads are processed in memory, not persisted `[V]`.
- **NFR-021 (M):** Per-tenant keys in an HSM or equivalent KMS, with rotation.
- **NFR-022 (M):** Independent penetration test before GA and annually after, SOC 2 Type II within 12 months of GA, ISO 27001 targeted `[I]`.
- **NFR-023 (M):** Admin and support access to tenants is time-boxed, logged and visible to the customer.
- **NFR-024 (M):** The connector and agent must be signed, reproducibly built and published with an SBOM.

### 12.4 Privacy and compliance

- **NFR-030 (M):** GDPR and CCPA compliant processing, DPA available, sub-processor list public.
- **NFR-031 (S):** HIPAA BAA available for P4 customers.
- **NFR-032 (S):** Regional log residency (US, EU, UK, APAC).
- **NFR-033 (M):** Admin-controlled privacy mode that redacts URLs paths and usernames in logs `[I]`.

### 12.5 Scalability

- **NFR-040 (M):** Support tenants from 1 to 5,000 users on the same architecture.
- **NFR-041 (M):** Support at least 5,000 tenants on one control plane in v1 (MSP scenario).

---

## 13. Small-business adaptations (where we deliberately differ from Zscaler)

Zscaler's August 2026 SMB initiative is partner-led, using standardised bundles, right-sized pricing, onboarding playbooks and reference architectures `[V]`. It does not describe a self-serve product. That is the opening.

| Area | Zscaler enterprise approach | SMB-ZTX approach |
|---|---|---|
| Onboarding | Professional services, phased rollouts | Self-serve wizard, under 30 minutes to first protected user |
| Policy | Rich rule builder | Recommended policy by default, three-screen simple mode |
| Packaging | Many SKUs and add-ons | Three tiers: Core (web), Access (ZTNA), Complete (all + DLP) |
| Pricing | Quote-based `[V: none published in sources read]` | Public per-user pricing, no minimum seats |
| Support | Tiered enterprise support | In-product chat, MSP-first escalation |
| Footprint | 200+ data centres `[V]` | Fewer PoPs through partner clouds, region-pinned |
| Operations | Dedicated SecOps | Automated triage, plain-language alerts, auto-remediation |

- **SMB-001 (M):** Setup wizard that connects an IdP, installs the agent through MDM or an email link, and enables a safe default policy.
- **SMB-002 (M):** "Safe defaults" policy pack: block known-bad categories, enable TLS inspection with sensible exemptions, block unsanctioned file-sharing uploads, require posture for sensitive apps.
- **SMB-003 (M):** Plain-language alerts with a single recommended action each.
- **SMB-004 (S):** Cyber-insurance questionnaire evidence export (MFA, EDR, segmentation, logging).
- **SMB-005 (S):** Free internet exposure scan to seed onboarding (Zscaler offers an "Internet Threat Exposure Analysis" `[V]`).

---

## 14. Parity matrix (summary)

| Zscaler capability | Section | Priority | Confidence |
|---|---|---|---|
| Secure web gateway, full TLS inspection | 6.1, 6.4 | M | V |
| Cloud firewall | 6.1 | M | V |
| URL filtering, cloud app control, file type control | 6.2 | M | V |
| Malware, ATP, IPS, DNS security | 6.3 | M | I |
| Cloud sandbox | 6.3 | M | V |
| Browser isolation | 6.3 | S | V |
| DLP, CASB | 6.5 | M | V/I |
| GenAI controls | 6.5, 7 | M/S | V |
| ZTNA, dark apps, connector stitching | 5.1–5.4 | M | V |
| AI app segmentation and recommendations | 5.3 | M | V |
| Browser access, privileged remote access | 5.5 | M | V |
| Private service edge, business continuity | 5.5 | S | V |
| B2B federation, extranet | 5.5 | M/S | V |
| Workload segmentation, OT/IoT | 5.5, 8 | C | V |
| Device posture, trusted networks | 4, 5.3 | M | V |
| Digital experience monitoring | 9 | S | V/I |
| SIEM/SOAR/API/Terraform | 10 | M | V/I |
| MSP multi-tenancy | 11 | M | I |

---

## 15. Open questions and risks

1. **Patent exposure.** Connector stitching (US 11,652,797 family, priority 2014-06-20, estimated expiry 2034) and handshake snooping (US 11,750,405 family) are Zscaler-assigned. Claim scope is unknown. Obtain a freedom-to-operate opinion before design freeze.
2. **Inspection versus end-to-end encryption.** ZPA-031 and ZPA-041 pull in opposite directions. Decide the default.
3. **Economics.** No Zscaler pricing was found. Establish whether a per-user price that SMBs accept covers PoP, egress and inspection costs.
4. **PoP strategy.** Build, or ride a partner network such as a hyperscaler or a CDN edge.
5. **Unverified module details.** Items marked `[I]` in sections 6.3, 6.5, 9 and 10 must be validated against Zscaler's data sheets, which were not readable in this research pass.
6. **Vendor-sourced statistics** (91%, 56%, 54% in ZPA marketing) are Zscaler claims.

---

## 16. Sources

Pages read in a browser or fetched as text during this research (accessed 2026-11-15):

1. Zscaler, "Zscaler Private Access" product page: https://www.zscaler.com/products-and-solutions/zscaler-private-access
2. Zscaler, "Zscaler Internet Access" product page: https://www.zscaler.com/products-and-solutions/zscaler-internet-access
3. Zscaler, "About Access Policy" (ZPA help): https://help.zscaler.com/zpa/about-access-policy
4. Zscaler and Carahsoft SMB press release, 2026-08-18: https://www.zscaler.com/press/zscaler-and-carahsoft-expand-partnership-deliver-enterprise-proven-zero-trust-security-smb
5. Zscaler white paper, "Implementing the NIST Zero Trust Architecture with Zscaler" (2022): https://www.zscaler.com/resources/white-papers/zscaler-implementing-NIST-zero-trust-architecture.pdf
6. Patent US 11,750,405 B2, "Encrypted traffic inspection in a cloud-based security system": https://patents.google.com/patent/US11750405B2/en
7. Patent US 11,652,797 B2, "Secure application access systems and methods via a lightweight connector and a cloud-based system": https://patents.google.com/patent/US11652797B2/en

Known from search result summaries only (pages not opened in full):

8. ZIA Policy Leading Practices Guide: https://help.zscaler.com/zscaler-deployments-operations/zia-policy-leading-practices-guide
9. ZPA Leading Practices Guide: https://help.zscaler.com/zscaler-deployments-operations/zpa-leading-practices-guide
10. Configuring Device Posture Profiles: https://help.zscaler.com/z-app/configuring-device-posture-profiles-zpa
11. Related filings referenced by search only: US 11,968,179; US 12,015,592; US 2021/0314301; US 2024/0129321 (not read).
