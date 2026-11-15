# Deferred features (not in RB1)

**Update (requirements v0.5):** the 34 items in REQUIREMENTS.md 17.1 are now **Must**. They stay outside RB1, so the "Priority in spec" column below now reads M for those rows. Deferral is a sequencing decision, not a statement that they are optional.

RB1 proves the core loop: identity and posture, then policy, then a brokered private connection or a filtered web request. Everything below is left out on purpose. Requirement IDs refer to REQUIREMENTS.md.

| Area | Deferred item | Priority in spec | Why deferred | Suggested phase |
|---|---|---|---|---|
| Web | **Browser isolation / secure workspace browser** (BYOD-001..005, spec 18.4) | S | Needs a remote-rendering fleet with real per-session cost. Does not change the core loop | R2, first |
| Web | TLS inspection (ZIA-040 and spec 6.4) | M | Privacy and per-tenant CA decisions open (DESIGN D5.8). Without it, `warn` on HTTPS cannot show a page and policy is host-only. Isolation is one way around that | R2 |
| Web | DLP, CASB, GenAI controls (spec 6.5, 7) | M / S | Depend on TLS inspection | R3 |
| Web | Sandbox, advanced threat protection | M | Needs file extraction and a detonation service | R3 |
| Web | Full firewall, DNS security, IPS (FW-xxx) | M | RB1 filters by host and category only | R2 |
| Web | Bandwidth control (BW-xxx) | S | Low value for first customers | R3 |
| Private access | Browser (clientless) access, privileged remote access | M | Needs a protocol gateway (HTTP, RDP, SSH) | R2 |
| Private access | B2B and third-party access, private service edge | M / S | Needs external-user identity and a locally hosted EN | R3 |
| Agent | Transparent tunnel driver, OS installers, auto-update | M | Per-OS native work. RB1 uses local proxies | R2 |
| Agent | EDR-based posture | S | RB1 posture is self-reported and spoofable by malware on the device | R2 |
| Identity | SAML, SCIM | M | OIDC covers Entra, Google and Okta first | R2 |
| Platform | Risk scoring and continuous trust (ARCH-007, spec 18.3) | S | Only the 5-minute posture re-check exists | R3 |
| Platform | Per-tenant CA (ARCH-021), KMS-held keys | M | RB1 uses one CA with the tenant in the subject | R2 |
| Platform | Multi-region, PoP fleet, data residency, SLAs | M / S | Build-versus-partner decision open (REQUIREMENTS section 15) | R3 |
| Operations | MSP multi-tenant console, SIEM streaming, Terraform | M | RB1 has a single-tenant admin API | R2 |
| Operations | Digital experience monitoring (DEX-xxx) | S | Needs agent probes and a data store | R3 |
| Network | Branch and cloud connectors (BR-xxx) | S / C | Reduced scope in the spec | R3 |
| SMB | Cyber-insurance evidence export, free exposure scan (SMB-004, 005) | S | Report and integration work | R2 |
| Assurance | Compliance certification, external penetration test, patent review | M | Process work. Patent review must precede any commercial use | before release |

Phases: **RB1** is the current build. **R2** makes it usable by a first design partner (inspection, isolation, installers). **R3** is breadth and scale.
