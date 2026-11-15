# Requirements Specification: Small-Business Zero Trust Platform

**Working name:** SMB-ZTX (placeholder)
**Goal:** Feature parity with the Zscaler Zero Trust Exchange (ZIA, ZPA, ZDX, data security) for organisations of roughly 5–250 people with no dedicated security team.
**Status:** Draft v0.5, 2026-11-15
**Audience:** Product, architecture, engineering

---

## 0. How to read this document

- Requirement IDs are stable (`ZIA-…`, `ZPA-…`). Priority is **M** (must, needed for parity), **S** (should), **C** (could).
- Each section has a **Parity source** line. Sources are listed in section 14. Nothing in this document comes from a Zscaler contract, a customer NDA or non-public material.
- **Confidence markers:** `[V]` means verified against a Zscaler page or patent read for this document. `[I]` means inferred from public descriptions or general industry practice, and must be checked before it is committed to a roadmap.
- "Parity" here means functional parity at the capability level. It does not mean copying Zscaler's implementation, and it does not mean equal global scale (see section 3, non-goals, and section 13).

### 0.1 Research limits (read first)

- **Revision 0.2 (2026-11-15):** the ZIA data sheet (©2026) and the ZPA data sheet (©2025), supplied as local PDFs, were read in full and are cited as `[DS-ZIA]` and `[DS-ZPA]`. Items they confirm are now `[V]`. Items they correct are marked "corrected in 0.2". Version 0.1 had wrongly said the data sheets were unreadable. They had simply not been opened.
- **Revision 0.3 (2026-11-15):** ten more PDFs were downloaded. Read in full: Zero Trust Firewall `[DS-FW]`, Bandwidth Control `[DS-BW]` (©2020, oldest source), Client Connector `[DS-ZCC]`, ZPA Private Service Edge `[DS-PSE]` (©2021). Searched for numbers only: the traffic-forwarding and universal-ZTNA reference architectures `[RA-FWD]`, `[RA-PSE]`. **Downloaded and converted but not reviewed: the two GOV data sheets, "Zero Trust for Users", and the PSE at-a-glance sheet.** FedRAMP-specific content is out of scope for v1 anyway.
- Sources disagree on minimum client OS versions: DS-ZPA (©2025) says Windows 8 and Android 9, while DS-ZCC (©2026) says Windows 10/11 and Android 10+. This spec follows the newer sheet.
- The Zscaler help portal (`help.zscaler.com`) renders client-side and several guessed URLs returned 404. Only the pages listed in section 16 were read, so some detail (for example exact DLP dictionaries and sandbox behaviour) is still `[I]`.
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
- **ARCH-007 (M):** Dynamic risk scoring and "active defense" feeding policy decisions `[V: named in NIST white paper; mechanics not described]`.
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

- **AGT-001 (M):** Single lightweight agent for Windows, macOS, Linux, iOS, iPadOS, Android and ChromeOS `[V: DS-ZIA lists Windows, macOS, iOS, iPadOS, Android, Linux; DS-ZPA adds ChromeOS 137+]`. Supported systems per the newer DS-ZCC `[V]`: Windows 10 and 11 on x64 and ARM64; macOS 14, 15, 26 and 27 on Intel and Apple Silicon; Linux desktops (RHEL, CentOS, Fedora, Ubuntu, Debian, openSUSE, Arch, Rocky, AlmaLinux); Android on ChromeOS and ChromeOS Flex; eLux and IGEL OS; iOS 17, 18, 26, 27; Android 10 to 16. (Corrected in 0.3: the older DS-ZPA minimums of Windows 8 and Android 9 are superseded.)
- **AGT-001a (M), new in 0.3:** **VDI support**: Windows 365, Azure Virtual Desktop, AWS WorkSpaces, Citrix, Omnissa Horizon, with multi-session support `[V: DS-ZCC]`. For SMB-ZTX: **S** for Windows 365/AVD/WorkSpaces, **C** for Citrix and Horizon.
- **AGT-001b (M), new in 0.3:** Traffic types: all ports and protocols, web only, client-to-client, and server-to-client `[V: DS-ZCC]`. IPv4 and IPv6 `[V]`.
- **AGT-001c (M), new in 0.3:** Tunnel transports: **QUIC and MASQUE, TLS 1.2/1.3, DTLS 1.2, WireGuard, and HTTP CONNECT**, with mutual TLS authentication and FIPS 140 compliance `[V: DS-ZCC]`. SMB-ZTX v1 minimum: TLS 1.3 plus one UDP transport (QUIC/MASQUE or WireGuard), mutual TLS. FIPS mode: **C**.
- **AGT-001d (S), new in 0.3:** Optimal data-centre selection, automatic or policy-based on geolocation, preferred PoPs, latency and traffic destination `[V: DS-ZCC]`.
- **AGT-002 (M):** Forwards web traffic to the nearest cloud node and private-app traffic to the broker. Connects outbound only and accepts no inbound connections `[V: US 11,652,797]`.
- **AGT-003 (M):** SSO sign-in through the tenant IdP `[V]`.
- **AGT-004 (M), confirmed in 0.3:** Connectivity modes: user-initiated, on-demand, **pre-login via machine tunnels**, always-on; per-app VPN and dual-tunnel on iOS; work profile on Android. Anti-tampering, and OTP or password protection of user logout, client exit and service stop `[V: DS-ZCC]`.
- **AGT-005 (M), confirmed in 0.3:** Device posture checks `[V: DS-ZCC]`: file path, registry key and value, certificate trust, client certificate with CRL, server-validated client certificate, firewall status, full-disk encryption, AD domain join, Entra domain join, process checks, antivirus detection, OS version, jailbreak detection, ownership variable, client release version, Wi-Fi SSID, client egress IP. EDR integrations: CrowdStrike (real-time detection, ZTA OS and sensor scores), Microsoft Defender, Carbon Black, Jamf (agent detection and risk level). SMB-ZTX v1 subset: disk encryption, firewall, OS version, AV/EDR present, certificate, domain/MDM join, jailbreak/root, with Defender, CrowdStrike, SentinelOne and Jamf signals.
- **AGT-006 (M):** Trusted-network detection that adjusts forwarding when the user is on a corporate network `[V: "trusted networks" criterion]`.
- **AGT-007 (M):** Forwarding profiles with bypass lists, and these traffic-forwarding methods for devices with and without the agent: agent, GRE tunnels, IPsec tunnels, PAC files `[V: DS-ZIA]`. Proxy chaining exists in Zscaler but its own sheet says it is "not recommended in production", so it is **C** here.
- **AGT-008 (S):** Fail-open and fail-closed settings per tenant and per app `[I]`. **Embedded captive-portal handling with optional network lockdown**, a local endpoint-firewall manager with local-LAN blocking, **device quarantine**, "no default route" environments, and custom company branding `[V: DS-ZCC]`.
- **AGT-009 (S):** Deployment `[V: DS-ZCC]`: MDM/UEM (Intune, Workspace ONE, Jamf, MaaS360, SCCM), Active Directory GPO, manual download, cloud-managed release updates **with rollback**, and **automatic distribution of the trusted root CA** for TLS inspection. Add a one-click "invite user by email" flow for P1.
- **AGT-012 (S), new in 0.3:** User provisioning `[V: DS-ZCC]`: SCIM, just-in-time SAML provisioning, emergency-user JIT, device auto-provisioning by machine key or token, AD/LDAP sync, manual and bulk user upload to a hosted user DB. Authentication options: SAML 2.0, OIDC, Kerberos, certificates and smart cards, MFA, **FIDO2 hardware tokens**, step-up authentication, browser-based authentication. SSO: Windows seamless, Kerberos, Microsoft Enterprise SSO plug-in, Apple Enterprise SSO, Okta SSO extension. SMB-ZTX v1: SAML, OIDC, MFA, FIDO2, SCIM, JIT; Kerberos and smart cards **C**.
- **AGT-013 (S), new in 0.3:** End-user notifications on desktop and OS for acceptable-use, service status, updates, re-authentication, inline data-security events, endpoint DLP workflows, access-policy events, threat protection, firewall/IPS/DNS blocks `[V: DS-ZCC]`. Built-in troubleshooting: automated encrypted log fetch, manual log export, automated and manual packet capture `[V]`.
- **AGT-014 (M), new in 0.3:** **Endpoint DLP** via the agent: removable storage, network shares, personal cloud-storage sync and printing `[V: DS-ZCC]`. Refines DATA-005.
- **AGT-015 (C), new in 0.3:** **Deception** on the endpoint: realistic decoy bookmarks, cookies, sessions and passwords that raise a high-fidelity alert when touched `[V: DS-ZCC]`.
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
- **ZPA-027 (M):** Time-based access and just-in-time access with an approval workflow, via Slack/Teams/email approver `[V: "Require Approval" exists; the workflow is `[I]`]`.
- **ZPA-028 (M):** Policy simulation: show who would lose access before a change is applied `[I]`.
- **ZPA-029 (M):** Additional policy types beyond access: timeout, client forwarding, and inspection policies `[I: names from general product knowledge]`.

### 5.4 Connection stitching

- **ZPA-030 (M):** The user-side node and the connector-side node each connect outbound, and the cloud joins them. Tokens from the central authority authorise each side `[V: US 11,652,797]`.
- **ZPA-031 (M):** End-to-end encryption using client-side and server-side certificates, so that broker nodes do not take part in the key exchange `[V: US 11,652,797]`.
- **ZPA-031a (M), corrected in 0.2:** v0.1 treated inline inspection as conflicting with ZPA-031. The ZPA data sheet shows the product flow: the user connects to the Zero Trust Exchange and authenticates with the IdP, holds a **single permanent TLS connection** to the service edge, downloads configuration including the device posture check, and the service edge stitches two outbound tunnels. Then, once connected, the **App Connector inspects the traffic inline** and AppProtection applies Layer 7 inspection `[V: DS-ZPA "How ZPA Works", steps 1–6]`. The design resolution is to inspect at the connector end, not in the broker. SMB-ZTX should do the same.
- **ZPA-032 (M):** Access decisions check both user and device policy before stitching `[V]`.
- **ZPA-033 (M):** Connect to the closest node at agent start, with automatic re-selection on failure `[V]`.

### 5.5 Access types

- **ZPA-040 (M):** **Browser access** (clientless) for web apps, RDP, SSH, with no agent, for unmanaged devices and contractors `[V]`.
- **ZPA-041 (M), raised from S in 0.2:** **AppProtection**: inline Layer 7 inspection of the entire application payload at the connector, blocking OWASP Top 10 attacks, with **custom signature support for virtual patching** of zero-days `[V: DS-ZPA]`. Integrated DLP, incident response and data classification for private apps `[V: DS-ZPA]`. Zscaler sells this as an add-on. For SMB-ZTX it should be included in the base tier, since small teams have no WAF.
- **ZPA-050 (S), new in 0.2:** **Legacy server-to-client (S2C) apps** such as VoIP and follow-me printing, through a network connector (a VM in front of the servers, connecting inside-out to VPN service edges in the cloud) `[V: DS-ZPA]`.
- **ZPA-051 (S), new in 0.2:** **Private cloud controller**: a per-tenant on-premises controller so users, private service edges and app connectors keep working when the cloud is unreachable, with automatic switchover to business-continuity mode `[V: DS-ZPA]`. Supersedes the vaguer ZPA-044.
- **ZPA-052 (M), new in 0.2:** **User portal**: one web portal where users reach authorised apps and privileged consoles `[V: DS-ZPA]`.
- **ZPA-053 (M), new in 0.2:** **Continuous health monitoring** of all apps, and **log streaming** to SIEM, in the base tier `[V: DS-ZPA]`.
- **ZPA-054 (S), new in 0.2:** **Source IP anchoring**: selectively forward app traffic from a known IP to destination servers `[V: DS-ZPA]`.
- **ZPA-055 (M), new in 0.2:** Browser access for unmanaged devices backed by **cloud browser isolation** (pixels only), with isolation policy over copy/paste, print and upload/download, and a Chrome Enterprise Browser posture integration `[V: DS-ZPA]`.
- **ZPA-056 (M), new in 0.2:** Connector and edge **platform support**: App Connector on AWS, GCP, Azure, Nutanix, VMware, OpenShift, Docker, Red Hat. Private service edge on the same minus OpenShift. Private cloud controller on AWS, Azure, VMware, Red Hat `[V: DS-ZPA]`. SMB subset for v1: AWS, Azure, GCP, VMware, Docker.
- **ZPA-057 (M), new in 0.2:** **Autonomous user-to-app segmentation**: discover apps by domain name and IP subnet, ML recommendations trained on access patterns, and live insights `[V: DS-ZPA]`. Strengthens ZPA-021.
- **ZPA-058 (M), new in 0.2:** **Risk-based policy engine** that continuously revalidates access on user, device, content and application risk `[V: DS-ZPA]`.
- **ZPA-042 (M):** **Privileged remote access**: clientless RDP, SSH, VNC to production systems for staff and third parties, with session recording `[V: capability named; recording is `[I]`]`.
- **ZPA-043 (M):** **Private service edge**: on-premises broker so in-office users reach local apps without a cloud hairpin `[V]`. Detail from DS-PSE and RA-PSE (new in 0.3): single-tenant, customer-hosted but vendor-managed, delivered as a lightweight VM or RPM, on-premises or in a public cloud. It registers with the cloud, downloads policy and **caches path-selection decisions**. It **caches access policies for weeks** so access survives an internet outage. Reference sizing: **4 CPU cores, 16 GB disk, 1 NIC, 500 Mbps maximum throughput per instance**, scaling by adding instances. It also serves remote users in countries with no public PoP, and customers whose regulation forbids cloud-hosted brokering. Admins can use the private edge and the cloud edge together, with automatic best-path choice `[V]`. Policy semantics move from source-IP-to-destination-IP to **user-to-hostname**, which is the main SMB selling point for removing internal firewalls.
- **ZPA-044 (M):** **Business continuity**: policy-enforced access during outages of the broker, via a local cached mode `[V: capability named]`.
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
- **ZIA-005 (M):** Cloud firewall (firewall-as-a-service) for non-web outbound traffic (DNS, FTP, RDP, SSH, Telnet and more) `[V: DS-FW]`. Detail below in 6.1a.
- **ZIA-006 (S):** Egress NAT with static IPs for allow-listing by SaaS vendors `[V: "Egress NAT" named]`.

### 6.1a Zero trust firewall, DNS and IPS (new in 0.3, from DS-FW)

- **FW-001 (M):** Application-aware rules: L3/L4 and FQDN, network applications identified by SNI and deep packet inspection, application services such as UCaaS identified by first-packet identification, IP/FQDN groups and heuristics `[V: DS-FW]`.
- **FW-002 (M):** Rule criteria: user, group, department, location (including a "remote users" location), application, with IdP and local user DB integration `[V: DS-FW]`.
- **FW-003 (M):** Deep packet inspection of non-web protocols (FTP, DNS, RDP, Telnet) to catch evasive traffic on **non-standard ports** `[V: DS-FW]`.
- **FW-004 (S):** **Endpoint App Control**: rules on the actual process, such as `PowerShell.exe` or `Chrome.exe`, for firewall, DNS and IPS `[V: DS-FW]`. Needs the agent.
- **FW-005 (S):** **Custom application services**: reusable objects grouping FQDNs or IPs with protocols and ports `[V: DS-FW]`.
- **FW-006 (M):** Managed IPS with behavioural signatures, plus **custom IPS with Snort-based rules** `[V: DS-FW]`. Snort rule import is the likely cheapest way to reach parity.
- **FW-007 (M):** DNS as a service `[V: DS-FW]`: trusted resolver with localisation, filtering rules (block, allow, redirect), DNS tunnelling and exfiltration detection using ML, and **DNS-over-HTTPS control** so DoH cannot bypass policy (needs TLS inspection). Optional resolution.
- **FW-008 (S):** FTP control and NAT control (NAT destination proxy and NAT forwarding) `[V: DS-FW]`.
- **FW-009 (M):** End-user notifications for firewall, DNS and IPS blocks (agent pop-up or browser page for DNS) so users know why access was denied `[V: DS-FW]`.
- **FW-010 (M):** **Forensically complete logs for every session** with user identity, device info, source and destination IP, port, country and threat category, kept six months `[V: DS-FW]`.
- **FW-011 (M):** Elastic handling of long-lived connections with native TLS inspection `[V: DS-FW]`.
- **FW-012 (S):** Zscaler gates the firewall: Standard has up to 10 firewall rules, up to 64 DNS rules, and aggregated logging only. Advanced has 1,000+ rules, user awareness, DPI applications, dynamic risk policy, endpoint app control, custom IPS, DNS tunnel detection and full logs, and is a paid add-on `[V: DS-FW]`. SMB-ZTX should not gate these by tier at small scale (see section 13).

### 6.1b Bandwidth control (new in 0.3, from DS-BW; ©2020, oldest source)

- **BW-001 (S):** Policies by traffic class (URL, URL category, or known cloud apps), location and time `[V: DS-BW]`.
- **BW-002 (S):** **Minimum** (guaranteed during contention) and **maximum** (cap) bandwidth per class, for example guarantee 40% for Office 365 and cap YouTube at 20% `[V: DS-BW]`.
- **BW-003 (C):** **Traffic shaping** (queueing, window shaping, throttling, dynamic video-resolution scaling) rather than packet-dropping policing `[V: DS-BW]`. Priority is **C** for SMB because most small sites have a single ISP link and few apps contend. Raised only for P4.

### 6.1c Branch and tunnel forwarding limits (new in 0.3, from RA-FWD)

- **BR-010 (S):** GRE tunnels: up to **1 Gbps each** when internal addresses are not behind NAT. IPsec tunnels: **400 Mbps maximum per tunnel**, formed from a single IP address, with more tunnels for more throughput `[V: RA-FWD]`. Use these as the parity figures for BR-001.
- **BR-011 (S):** Documented MTU/MSS guidance for tunnels (GRE MTU 1476 and MSS 1436 on a 1500-byte link) `[V: RA-FWD]`.

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
- **ZIA-016 (M):** Bandwidth control to prioritise business-critical apps over recreational traffic `[V: DS-ZIA]`. Time quotas and browser/user-agent control remain `[I]`.
- **ZIA-017 (M), new in 0.2:** URL filtering actions are **allow, block, caution, or isolate** `[V: DS-ZIA]`.
- **ZIA-018 (S), new in 0.2:** **Dedicated IP** (a vendor-assigned IP for your organisation, for SaaS allow-listing) and **Bring Your Own IP** `[V: DS-ZIA]`. Refines ZIA-006.
- **ZIA-019 (M), new in 0.2:** **Dynamic, risk-based access and security policy** that adapts automatically to user, device, application and content risk `[V: DS-ZIA]`.

### 6.3 Threat protection

- **ZIA-020 (M):** Malware and antivirus scanning inline `[V]`.
- **ZIA-021 (M):** Advanced threat protection: malware, ransomware, supply-chain attacks and phishing, with policies set against the organisation's risk tolerance `[V: DS-ZIA]`. Botnet/C2 and cryptomining specifics remain `[I]`.
- **ZIA-022 (M):** Cloud IPS across all ports and protocols, working across firewall, sandbox, DLP and CASB, with **custom IPS signatures** for targeted attacks `[V: DS-ZIA]`.
- **ZIA-022a (M), new in 0.2:** **DNS security**: route suspicious C2 connections to deep inspection, and block DNS requests to known-bad destinations, on all ports and protocols `[V: DS-ZIA]`.
- **ZIA-022b (M), new in 0.2:** **Traffic capture**: capture decrypted traffic by policy criteria for forensics, with no extra appliance `[V: DS-ZIA]`.
- **ZIA-022c (M), new in 0.2:** **Correlated threat insights**: alerts correlated with threat score, affected asset and severity `[V: DS-ZIA]`.
- **ZIA-022d (M), new in 0.2:** **Application isolation** for agentless unmanaged-device access to SaaS, cloud and private apps, with copy/paste, upload/download and print control `[V: DS-ZIA]`.
- **ZIA-022e (C), new in 0.2:** **IoT device visibility**: automatic discovery and ML classification of IoT devices, servers and unmanaged devices `[V: DS-ZIA]`.
- **ZIA-022f (S), new in 0.2:** **Post-quantum cryptography visibility**: inspect and report on classical and PQC traffic, including "harvest now, decrypt later" exposure `[V: DS-ZIA; claim is Zscaler's]`.
- **ZIA-023 (M):** Cloud sandbox for unknown files with AI-driven instant verdicts, and large-file sandboxing `[V: product page mentions "sandboxing code and unknown or large files with instant AI-verdicts"]`.
- **ZIA-024 (M):** Browser isolation for risky or uncategorised sites `[V: search result mentions a file isolated on a remote browser]`.
- **ZIA-025 (S):** Threat intelligence feed updates pushed to enforcement nodes in near real time `[V: central authority distributes threat updates]`.

### 6.4 TLS inspection design

Parity source: US 11,750,405 `[V]`.

- **ZIA-030 (M):** Man-in-the-middle interception proxy that terminates and re-establishes TLS, using a per-tenant CA `[V]`.
- **ZIA-031 (M):** Alternative **handshake-snooping** mode for apps with certificate pinning, which derives keys from the observed handshake and inspects traffic without breaking the tunnel `[V: patent description]`. **Patent risk: high. Needs counsel.**
- **ZIA-032 (M):** Automatic exemption lists for pinned apps, banking and health categories, with admin override `[I]`.
- **ZIA-033 (M):** Automated trust of the tenant CA on managed devices (MDM profile, agent-installed) `[I]`.
- **ZIA-034 (M):** Automated inspection coverage for 30+ developer tools (git, package managers, container registries, CLIs), which otherwise break on custom CAs `[V: product page mentions 30+ dev tools]`.

### 6.5 Data protection

- **DATA-001 (M):** Inline DLP across all inspected traffic, with **exact data match (EDM), optical character recognition (OCR) and machine learning** classification `[V: DS-ZIA]`, plus built-in dictionaries (PII, PCI, health, secrets) and custom patterns `[I: dictionary names]`. DLP violations are reported as compliance events `[V]`.
- **DATA-002 (M):** Two-part CASB `[V: DS-ZIA]`: **inline** control of sanctioned and unmanaged apps (cloud app control, shadow IT report, tenancy restriction) and **out-of-band** API scanning of SaaS and cloud platforms to find sensitive data at rest and auto-remediate, for example by revoking risky or external shares. Target apps for v1: Microsoft 365, Google Workspace, Slack, GitHub `[I: app list]`.
- **DATA-002a (M), new in 0.2:** **Tenancy restriction** (allow only the corporate tenant of a SaaS app) and **Shadow IT report** `[V: DS-ZIA Data Protection Standard]`.
- **DATA-003 (S):** Cloud (IaaS) posture checks `[I]`.
- **DATA-004 (M):** Generative AI controls: block or allow AI apps by category, real-time inspection of prompts (Zscaler cites Microsoft Copilot inspection) `[V]`.
- **DATA-005 (M):** Endpoint DLP and USB/removable media control through the agent `[I]`.
- **DATA-006 (M):** Email DLP and exact data match / index document match `[I]`.
- **DATA-SOV (S):** Data and content sovereignty: egress NAT, geolocalised content, in-country logging `[V: three features named on product page]`.

---

## 7. AI and developer-workflow security (differentiator, not strict parity)

Zscaler is positioning for the AI era (ZIA mentions Copilot prompt inspection and dev-tool inspection) `[V]`. For P2 customers the following are strongly recommended:

- **AI-001 (M):** Per-tool allow lists for AI coding assistants and agents, identity-bound to the human operator.
- **AI-002 (M):** Agent-to-resource access through the same broker as human access: scoped, short-lived, logged `[I]`.
- **AI-003 (M):** Prompt and response DLP for sanctioned AI tools.
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

- **DEX-001 (M):** Per-user and per-app experience score from agent probes (web, network path, device health).
- **DEX-002 (M):** Hop-by-hop path analysis from device to app, separating device, Wi-Fi, ISP, cloud and app causes.
- **DEX-003 (M):** Device health: CPU, memory, disk, Wi-Fi signal.
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
- **ADM-006 (M), corrected in 0.2:** Real-time log search and dashboards. Zscaler retains data for a **rolling six months or less depending on product**, with purchasable extra storage `[V: DS-ZIA]`, so the default here is 6 months (v0.1 said 30 days) and longer retention is a paid option.
- **ADM-006a (M), new in 0.2:** Log streaming to SIEM in two forms `[V: DS-ZIA]`: **cloud streaming** (Cloud NSS, which Zscaler gates at more than 500 users) and **streaming to an on-premises SIEM** (Nanolog Streaming Service). SMB-ZTX should offer cloud streaming with no seat minimum.
- **ADM-006b (M), new in 0.2:** Logs are **never written to disk** in the inspection path, with granular control over where logging happens, read-only roles, and **username anonymisation/obfuscation** `[V: DS-ZIA]`. Refines NFR-033.
- **ADM-007 (M):** "Forensically complete" logging of every transaction `[V: product page claim]`, with a documented field list.
- **ADM-008 (S):** Scheduled reports (executive, compliance) as PDF/email.
- **ADM-009 (M):** Weekly "security digest" for P1 users in plain language.
- **ADM-010 (M):** **MSP console:** multi-tenant parent/child hierarchy, policy templates, cross-tenant dashboards, delegated admin, white-label branding, usage-based billing export `[I]`.

---

## 12. Non-functional requirements

All figures are engineering targets set for this document, unless marked `[V]`.

### 12.1 Performance

- **NFR-000 (M), new in 0.2 (Zscaler's published SLAs):** availability **99.999% measured by transactions lost**, proxy latency **under 100 ms including with threat and DLP scanning on**, and **100% capture of known viruses and malware** `[V: DS-ZIA]`. These are vendor SLA claims, not measurements. Parity means publishing equal or stronger SLAs. Zscaler's own claim of "up to 40% faster than legacy architectures" is marketing and is not a requirement.
- **NFR-001 (M):** Added latency for web traffic under 20 ms at p50 and under 60 ms at p95, within a region that has a PoP. (Stricter than Zscaler's 100 ms SLA, so it is a differentiator target, not a parity floor.)
- **NFR-002 (M):** Private-app connection set-up under 500 ms at p95 after the first session.
- **NFR-003 (M):** Throughput per user of at least 100 Mbps with TLS inspection on.
- **NFR-004 (S):** Policy propagation to all nodes in under 60 seconds.

### 12.2 Availability and resilience

- **NFR-010 (M), corrected in 0.2:** Data-plane availability of **99.999%** measured by transactions lost, to match Zscaler's published SLA `[V: DS-ZIA]`. v0.1 had 99.99%, which was below parity. A 99.999% target is a serious cost driver (multi-region, active-active). If it is not affordable at SMB price points, state 99.99% explicitly as a parity gap rather than leaving it implicit.
- **NFR-011 (M):** No single node, PoP, or control-plane failure drops established sessions `[V: control/data plane independence]`.
- **NFR-012 (M):** Deterministic fail-open or fail-closed behaviour per tenant, documented and testable.

### 12.3 Security of the platform itself

- **NFR-020 (M):** Customer payloads are processed in memory, not persisted `[V]`.
- **NFR-021 (M):** Per-tenant keys in an HSM or equivalent KMS, with rotation.
- **NFR-022 (M):** Independent penetration test before GA and annually after. Zscaler lists **FedRAMP, ISO 27001, SOC 2 Type II, SOC 3 and NIST 800-63C** `[V: DS-ZIA]`. SMB-ZTX target: SOC 2 Type II within 12 months of GA, ISO 27001 within 18, FedRAMP out of scope for v1 (section 2.2).
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

### 13.1 Zscaler packaging and seat minimums (new in 0.2/0.3, from DS-ZIA, DS-ZPA, DS-FW)

All ZIA editions are **priced per user**, with some products priced differently. No prices are published. Quotes go through an account team `[V: DS-ZIA]`. What the sheets do show is where Zscaler's packaging is hostile to a small customer:

| Item | Zscaler rule | Source |
|---|---|---|
| ZIA editions | Essentials Platform, and Zscaler Platform (full SSE) | DS-ZIA |
| ZPA inside the ZIA Essentials edition | "1 user per 20 subscribed users (Min: 500 subscribed users)", so a 100-seat firm gets no ZPA from Essentials | DS-ZIA |
| ZPA editions | Essentials, Clientless, ZPA Platform, Zscaler Platform | DS-ZPA |
| App segments | **10** (Essentials) or **20** (other ZPA editions) | DS-ZPA |
| Third-party access add-on | minimum 500 users | DS-ZPA |
| Business-continuity cloud add-on | minimum 500 users | DS-ZPA |
| Deception | minimum 500 users | DS-ZPA |
| VPN service edges (legacy apps) | add-on, minimum 50 users | DS-ZPA |
| Autonomous segmentation, AppProtection, browser isolation, private-app data protection | paid add-ons | DS-ZPA |
| Cloud NSS log streaming | gated at more than 500 users | DS-ZIA |
| Zero Trust Browser Advanced | 1.5 GB of traffic per user per month, pooled | DS-ZIA |
| Workload traffic included | 1 GB (Essentials) or 2 GB (Platform) per subscribed user per month | DS-ZIA |
| Firewall Advanced | separate licence (ZS-CTP-1), Essentials plus that licence at minimum | DS-FW |
| Support | Standard included, Support Plus separate | DS-ZIA |

Implication: Zscaler's enterprise packaging has **many 500-user minimums**, plus 10/20 app-segment caps. The August 2026 SMB initiative promises "right-sized" packaging but does not state its numbers `[V: press release]`, so it is not known whether these minimums are lifted for SMB bundles. That is the clearest product opening.

- **SMB-006 (M), new in 0.3:** **No seat minimums** on any feature, and no per-feature gating at small scale. Zscaler's 500-user minimums and 10/20 app-segment caps are the main gaps to avoid. Use soft fair-use limits instead.
- **SMB-007 (S), new in 0.3:** Per-user pricing with all inspection features (AppProtection, advanced firewall, isolation up to a fair-use traffic cap, log streaming) in the top tier.

- **SMB-001 (M):** Setup wizard that connects an IdP, installs the agent through MDM or an email link, and enables a safe default policy.
- **SMB-002 (M):** "Safe defaults" policy pack: block known-bad categories, enable TLS inspection with sensible exemptions, block unsanctioned file-sharing uploads, require posture for sensitive apps.
- **SMB-003 (M):** Plain-language alerts with a single recommended action each.
- **SMB-004 (M):** Cyber-insurance questionnaire evidence export (MFA, EDR, segmentation, logging).
- **SMB-005 (S):** Free internet exposure scan to seed onboarding (Zscaler offers an "Internet Threat Exposure Analysis" `[V]`).

---

## 14. Parity matrix (summary)

| Zscaler capability | Section | Priority | Confidence |
|---|---|---|---|
| Secure web gateway, full TLS inspection | 6.1, 6.4 | M | V |
| Cloud firewall | 6.1 | M | V |
| URL filtering, cloud app control, file type control | 6.2 | M | V |
| Malware, ATP, IPS, DNS security | 6.1a, 6.3 | M | V |
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
| Digital experience monitoring | 9 | S | V (named), I (detail) |
| SIEM/SOAR/API/Terraform | 10 | M | V/I |
| MSP multi-tenancy | 11 | M | I |

---

## 15. Open questions and risks

1. **Patent exposure.** Connector stitching (US 11,652,797 family, priority 2014-06-20, estimated expiry 2034) and handshake snooping (US 11,750,405 family) are Zscaler-assigned. Claim scope is unknown. Obtain a freedom-to-operate opinion before design freeze.
2. **Inspection versus end-to-end encryption.** ZPA-031 and ZPA-041 pull in opposite directions. Decide the default.
3. **Economics.** No Zscaler pricing was found. Establish whether a per-user price that SMBs accept covers PoP, egress and inspection costs.
4. **PoP strategy.** Build, or ride a partner network such as a hyperscaler or a CDN edge.
5. **Remaining unverified details.** After revisions 0.2 and 0.3, `[I]` items remain mainly in sections 6.3 (botnet and cryptomining specifics), 6.5 (DLP dictionary names, email DLP), 9 (digital experience monitoring: no ZDX data sheet was read), 10 (specific IdP and SOAR vendors) and 11 (MSP console, which is not described in any sheet read). Next sources: the ZDX data sheet, the ZIA DLP and CASB data sheets, and the Cloud Browser Isolation sheet.
7. **Conflicting vendor numbers.** The sheets give "160+" data centres (DS-ZIA, DS-ZPA, DS-ZCC), "more than 150" in some boilerplate, and the August 2026 press release says "200+". Treat PoP count as marketing, not a requirement.
8. **Sheet dates.** DS-BW is from 2020 and DS-PSE from 2021. Product behaviour may have changed.
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

Data sheets and reference architectures, read from PDFs the user supplied or that were downloaded (not republished in this repository):

- `[DS-ZIA]` Zscaler Internet Access data sheet (©2026): https://www.zscaler.com/resources/data-sheets/zscaler-internet-access.pdf
- `[DS-ZPA]` Zscaler Private Access data sheet (©2025): https://www.zscaler.com/resources/data-sheets/zscaler-private-access.pdf
- `[DS-FW]` Zero Trust Firewall data sheet (©2026): https://www.zscaler.com/resources/data-sheets/zscaler-firewall.pdf
- `[DS-ZCC]` Client Connector data sheet (©2026): https://www.zscaler.com/resources/data-sheets/zscaler-mobile-app.pdf
- `[DS-BW]` Bandwidth Control data sheet (©2020): https://www.zscaler.com/resources/data-sheets/zscaler-bandwidth-control.pdf
- `[DS-PSE]` ZPA Private Service Edge data sheet (©2021): https://www.zscaler.com/resources/data-sheets/zpa-private-service-edge.pdf
- `[RA-FWD]` Traffic Forwarding in ZIA reference architecture (searched for tunnel limits only): https://www.zscaler.com/resources/reference-architectures/traffic-forwarding-in-zscaler-internet-access.pdf
- `[RA-PSE]` Universal ZTNA with Private Service Edge reference architecture (searched for sizing only): https://www.zscaler.com/resources/reference-architectures/universal-ztna-zpa-private-service-edge.pdf
- Downloaded, not reviewed: `zscaler-private-access-gov.pdf`, `zscaler-internet-access-gov.pdf`, `zero-trust-for-users.pdf`, `zpa-private-service-edge-at-a-glance.pdf`.

Known from search result summaries only (pages not opened in full):

8. ZIA Policy Leading Practices Guide: https://help.zscaler.com/zscaler-deployments-operations/zia-policy-leading-practices-guide
9. ZPA Leading Practices Guide: https://help.zscaler.com/zscaler-deployments-operations/zpa-leading-practices-guide
10. Configuring Device Posture Profiles: https://help.zscaler.com/z-app/configuring-device-posture-profiles-zpa
11. Related filings referenced by search only: US 11,968,179; US 12,015,592; US 2021/0314301; US 2024/0129321 (not read).

---

## 17. Change log

- **0.1** First draft from product pages, one help page, the NIST white paper and two patents.
- **0.2** Read the ZIA and ZPA data sheets. Corrected: ZPA inspection design (ZPA-031a), availability (NFR-010, 99.99% to 99.999%), log retention (ADM-006, 30 days to 6 months). Added: ZPA-050 to ZPA-058, ZIA-017 to ZIA-019, ZIA-022 to ZIA-022f, DATA-002a, ADM-006a/b, NFR-000, and section 13.1 (packaging and seat minimums).
- **0.3** Read the firewall, bandwidth control, Client Connector and Private Service Edge sheets. Corrected minimum client OS versions (AGT-001). Added: AGT-001a to AGT-001d, AGT-012 to AGT-015, sections 6.1a, 6.1b and 6.1c, expanded ZPA-043, SMB-006 and SMB-007.
- **0.4** Added `COMPETITIVE-ANALYSIS.md` (Cato Networks, Palo Alto Networks) and section 18 below. PDFs now live in the git-ignored `.doc/` folder.
- **0.5** Product decision: 34 requirements promoted from **S** to **M** (see 17.1). Parity-matrix rows for isolation, DEX and risk-based policy follow. No requirement was demoted.

### 17.1 Promoted to Must in 0.5

| Group | IDs |
|---|---|
| Inspection on top of the proxy | ZIA-022b, ZIA-022c, ZIA-022d, ZIA-031, ZIA-034, ZIA-040 |
| Data protection | DATA-005, DATA-006, AGT-014 |
| Private access extras | ZPA-027, ZPA-043, ZPA-044, ZPA-055, ZPA-074 |
| Browser isolation and unmanaged devices | ZIA-024, BYOD-001, BYOD-002, BYOD-003, BYOD-004 |
| Risk and adaptive policy | ARCH-007, ZPA-072, ZPA-073 |
| Digital experience | DEX-001, DEX-002, DEX-003 |
| AI controls | AI-001, AI-002, AI-003 |
| SMB operations | ADM-009, ADM-020, OPS-004, OPS-005, SMB-004, ZPA-028 |

Consequences to carry into the other documents:

- **ZIA-040 (TLS inspection by default) is now Must**, so DESIGN open question 4 is closed in favour of decryption. The privacy and per-tenant CA work (ARCH-021) moves from "deferred" to "required before first customer".
- Several of these are the hardest items in the spec (single-pass inspection, DLP, risk scoring). Making them Must raises cost and time substantially. The roadmap phasing, not the priority, now carries the sequencing.
- RB1 scope does **not** change. It remains a proof of the core loop, and it now explicitly leaves out Must items. Every Must item outside RB1 is tracked in ROADMAP.md.

---

## 18. Ideas adopted from Cato Networks and Palo Alto Networks (new in 0.4)

Detail, sources and research limits are in `COMPETITIVE-ANALYSIS.md`. These are **ideas** for differentiation. They are not part of Zscaler parity. Each cites its source. Cato's SPACE white paper and Palo Alto's current spec sheet were not read, so details here come from solution briefs, one knowledge-base article, one blog post and old data sheets.

### 18.1 Platform design

- **ARCH-030 (M) one rule base.** All enforcement (firewall, web, SaaS, DLP, private access) uses a single policy model and one rule list, instead of separate modules with an evaluation order `[V: Cato "single policy engine"; contrast with Zscaler's multi-module order in 6.2]`. For a customer with no security team this removes the main source of mistakes. Internally the engine may still run modules in order, but the admin sees one list.
- **ARCH-031 (M) decrypt once, inspect in one pass.** TLS is terminated once per flow and all engines work on the same decrypted stream `[V: Cato SPACE, Palo Alto "single-pass"]`. Needed to meet NFR-001.
- **ARCH-032 (S) open per-flow data store.** Every flow's user, device, app, data and verdict context is stored once and queryable through the API and SIEM export `[V: Cato "open data lake"]`. Feeds ADM-005, INT-004 and the AI analyst in 18.5.
- **NFR-050 (M) make-before-break maintenance.** Before upgrading a node, move existing tunnels to another node, then upgrade. No user session may drop for a routine release `[V: description of Cato application US 2026/0186764 A1; claims unread, patent risk unknown]`. Counsel review needed before copying the mechanism. The requirement (no drops on upgrade) is a goal, not a copy of their method.
- **NFR-051 (S) no hyperscaler dependency for the data plane**, or a documented fallback, so a single cloud vendor outage does not take the service down `[V: Cato claim; vendor marketing]`.

### 18.2 Private access additions

- **ZPA-060 (M) connector groups by default.** Applications bind to a connector **group**, not a single connector, for failover and load distribution `[V: Cato Private Access]`. Refines ZPA-011.
- **ZPA-061 (M) overlapping-IP safe publishing.** Publish an app by DNS name, hide the real address behind a carrier-grade-NAT range (Cato defaults: 100.64.0.0/16 management, 100.65.0.0/16 applications, user-overridable) `[V: Cato Private Access]`. Lets a small company onboard a partner or an acquired business with no re-addressing.
- **ZPA-062 (M) default-deny and user-initiated only in v1.** Server-initiated and bidirectional flows are out of scope for the basic ZTNA tier and go to the connector-site tier (ZPA-050) `[V: Cato states the same split]`.
- **ZPA-063 (S) outbound DTLS or QUIC from the connector** (UDP-based transport, avoids TCP-over-TCP) `[V: Cato uses DTLS; Zscaler client uses DTLS and QUIC per AGT-001c]`.

### 18.3 Continuous trust and identity (Palo Alto "ZTNA 2.0")

- **ZPA-070 (M) continuous trust assessment.** Re-score a session when device posture, location or network changes (for example public Wi-Fi, or a session resumed from a new device) `[V: Palo Alto blog]`. Zscaler's equivalent is ZPA-058.
- **ZPA-071 (M) risk-based MFA step-up.** Ask for a stronger factor when the user opens a more sensitive app or the risk score rises, not only at sign-in `[V: Palo Alto blog]`.
- **ZPA-072 (M) fast group reaction.** Policy reacts to risk before the identity provider's group membership changes (for example drop a user into a "restricted" group in the product) `[V: Palo Alto blog, "dynamic user group monitoring"]`.
- **ZPA-073 (M) enforce at the first packet** to prevent lateral movement before a connection opens `[V: Palo Alto blog]`.
- **ZPA-074 (M) sub-application control.** Rules on the application and on parts of it (for example allow reading an admin console, block its upload function) using app identification `[V: Palo Alto "app and sub-app"; marketing claim, mechanics not read]`.
- **ZIA-040 (M) credential-theft prevention.** Detect a corporate password being typed into an untrusted site and block it, by comparing entered credentials with corporate ones `[V: Palo Alto blog]`. High value for phishing, which is the top SMB risk.
- **ADM-020 (M) change modelling.** Before saving a policy change, show who would gain or lose access and which flows would break `[V: Palo Alto AIOps "change-management modelling and policy analysis"]`. Refines ZPA-028.

### 18.4 Unmanaged devices: a secure workspace browser

The most distinctive idea for a business with contractors and personal laptops and **no mobile device management**.

- **BYOD-001 (M).** A managed browser (or browser profile) that gives an isolated corporate workspace on an unmanaged device, installable in minutes, with no agent and no MDM `[V: Palo Alto Prisma Access Browser white paper]`.
- **BYOD-002 (M).** Last-mile data controls: block screenshots, camera and microphone, mask sensitive fields, watermark, encrypt downloaded files `[V: same]`.
- **BYOD-003 (M).** Last-mile access controls: login restrictions, MFA, admin approval for sensitive actions `[V: same]`.
- **BYOD-004 (M).** Re-check device posture about every 90 seconds and defend against malicious extensions `[V: same; the 90-second figure is Palo Alto's]`.
- **BYOD-005 (C).** Inspect browser traffic that proxies miss (QUIC, ECH, large files) because inspection happens inside the browser `[V: same]`.

This overlaps ZPA-055 (isolated browser access) and ZIA-022d (application isolation). The difference is that the browser runs on the user's device, not as streamed pixels. Both models should be evaluated. A secure browser is cheaper to run (no remote rendering farm) but needs a native app per OS.

### 18.5 Operations for people without a security team (the main Cato lesson)

- **OPS-001 (M) three management models:** self-service, co-managed (customer delegates changes or troubleshooting to the vendor or partner), and fully managed by a partner `[V: Cato solution brief]`. Maps to personas P1 and P3.
- **OPS-002 (M) managed detection and response** offered by the vendor or MSP, with a monthly plain-language report of threats, risk levels and affected users `[V: Cato "Managed XDR" and monthly report]`.
- **OPS-003 (S) named customer success contact** for the first 90 days `[V: Cato "Customer Success Engineer"]`.
- **OPS-004 (M) AI-written incident stories** that correlate flow, device and identity signals into a short, ordered investigation with guided remediation, using playbooks `[V: Cato XDR; Gen-AI claim is marketing]`. For SMB the first version can be rule-based.
- **OPS-005 (M) intent-driven policy UI** and **autonomous policy** suggestions: the product proposes rules from observed traffic and the admin accepts or rejects `[V: Cato "autonomous policies, automated posture management, intent-driven UI"; mechanics unread]`. Complements ZPA-057.
- **OPS-006 (S) SaaS security posture management:** continuous check of Microsoft 365, Google Workspace and similar settings against a known framework, with one-click fixes `[V: Palo Alto SSPM]`. Refines DATA-003.
- **OPS-007 (S) explicit-proxy mode** so a customer can move from an existing proxy or PAC setup with no network change `[V: Palo Alto]`. Matches AGT-007.

### 18.6 Network edge (only if the product includes branches, see section 8)

- **BR-020 (C) zero-touch edge device or image** with active/active multi-link, per-app dynamic path selection, packet-loss mitigation (including duplicating packets for critical apps), BGP, and high availability at no extra recurring charge `[V: Cato Socket]`. Priority is **C** because Zscaler leaves this to the customer and building a backbone is a different business. A software-only variant (router or VM) is the realistic SMB version.
- **BR-021 (C) agentless cloud connection** through the cloud provider's own IPsec gateway, with no virtual appliance `[V: Cato]`. Complements BR-003.
- **BR-022 (C) smart egress:** application-level rule choosing the PoP that exits specific traffic nearest the SaaS or cloud instance `[V: Cato]`. Complements ZIA-006.

### 18.7 Endpoint-assisted enforcement

- **FW-020 (C) process-aware traffic steering.** The agent maps each connection to its process hash. Traffic from unknown or risky processes is steered for deeper inspection, trusted processes keep the short path, and the product can ask the agent to stop a process `[V: description of Palo Alto US 12,003,485; claims unread; active to about 2037 per Google's estimate]`. **Patent risk is real.** Zscaler's Endpoint App Control (FW-004) is a related but different feature. Get counsel review first.
- **ZPA-075 (C) bundled endpoint protection**, using a licensed third-party engine, in the same console `[V: Cato EPP uses a SentinelOne engine]`.

### 18.8 Packaging, MSP and compliance

- **SMB-020 (M) service-provider multi-tenancy** with per-tenant separation, white label and usage-based billing `[V: Palo Alto "Clean Pipe" for service providers; Cato's partner-managed model]`. Refines ADM-010.
- **SMB-021 (M) logging included.** Palo Alto's 2020 sheet makes its data lake a required, paid add-on, Zscaler includes 6 months, so default to included `[V: 2020 sheet, may have changed]`.
- **SMB-022 (S) exclusions from inspection** for privacy-sensitive categories (banking, health) with one switch, and a published "inspected data is never stored" commitment `[V: Cato brief; Zscaler has similar]`. Refines ZIA-032.
- **NFR-060 (S) compliance targets** to publish: PCI DSS 4.0, SOC 1 and 2, ISO 27001, 27017, 27018, 27701 `[V: Cato's list]`. Zscaler lists FedRAMP, ISO 27001, SOC 2 and 3. Union is the long-term target.

### 18.9 Not adopted

- Building a private global backbone (Cato) and SD-WAN hardware (both): capital intensive, outside "small business, no network team".
- 5G appliances, SD-branch switching with uPoE (Palo Alto): hardware business.
- Marketing statistics (95% of web threats stopped inline, 10x better SLAs, and so on): vendor claims with no method.
