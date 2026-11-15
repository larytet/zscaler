# Gap register: requirements (v0.8) against the code

First pass, written 2026-11-15 from the requirements text and the repository. It has not been reviewed by anyone else. "Mentioned" means the requirement ID appears in code comments, tests, STATUS.md, RESULTS.md or README.md; an ID that is not mentioned may still be partly met, and a mentioned one may be met only in a basic form (STATUS.md says which). This file lists what is **missing or only basic**, so it can be worked through one gap at a time.

## Must requirements by family

There are 174 Must requirements. 59 are mentioned somewhere in code, tests or status files; 115 are not.

| Family | Must | Mentioned | Not mentioned |
|---|---|---|---|
| ADM | 12 | 2 | 10 |
| AGT | 12 | 9 | 3 |
| AI | 3 | 3 | 0 |
| ARCH | 14 | 4 | 10 |
| BYOD | 4 | 4 | 0 |
| DATA | 6 | 3 | 3 |
| DEX | 3 | 3 | 0 |
| FW | 8 | 0 | 8 |
| INT | 5 | 0 | 5 |
| NFR | 17 | 0 | 17 |
| OPS | 4 | 2 | 2 |
| SMB | 7 | 3 | 4 |
| WB | 10 | 10 | 0 |
| ZIA | 28 | 8 | 20 |
| ZPA | 41 | 8 | 33 |

## Work queue: gaps that fit the current architecture (no new subsystem)

Each is done as one subtask: change, test, STATUS.md, commit, push. Order is by value to a small business without a security team.

| # | Requirement | Gap | State |
|---|---|---|---|
| G1 | ADM-004 | Policy change history, diff and rollback | **done (S16)**: last 50 versions kept per policy, who saved each, plain-language diff, rollback as a new version; no console page |
| G2 | ADM-002 | Roles owner, admin, helpdesk, auditor, read-only with a permission matrix, and an owner-only API to manage administrators | **done (S23)**; no console page |
| G3 | INT-004, ADM-006a | Log streaming to a SIEM (HTTPS and syslog) with a documented schema | **done (S24)**; no console page, no S3 or Blob target, no on-premises collector |
| G4 | DATA-002a | Tenancy restriction (only the corporate tenant of Microsoft 365, Google Workspace, Slack), by adding the vendor's header on inspected traffic | **done (S25), not checked against the live vendor services**; the general shadow-IT report (beyond AI tools) is still missing |
| G5 | ZIA-013 | File type control on inspected uploads and downloads (by extension, content type and file signature) | **done (S26)**; no content disarm, archives not opened, no console page |
| G6 | ADM-006, FW-010, ADM-007 | Decision logs kept six months and searchable by date | **done on the control plane (S27)**; the enforcement node's own file is still not rotated; no console page; no dashboards |
| G7 | NFR-033, ADM-006b | Privacy mode that hides usernames (and paths) in logs | **done for decision records (S28)**; audit log, alert and e-mail text, user and device lists are not covered; paths were never logged |
| G8 | ZIA-014 | Reason strings on block pages for every deny reason, not only some | **done for the web proxy (S29)**; private-app refusals (SOCKS) still carry no message to the user |
| G9 | INT-002 | SCIM provisioning of users and groups | **done (S30), not tested against a real Entra ID or Okta**; no Enterprise User extension, no bulk, no group nesting |
| G10 | NFR-012 | Per-tenant fail-open or fail-closed setting, documented and tested | **done (S31)** for two faults: a node cut off from the control plane, and a node that cannot write its log; other faults are not covered |
| G11 | ZIA-011 | Cloud app control: a catalogue of apps with actions (upload, post, share) as rule conditions | **done (S32)**; the built-in catalogue is small and unverified against the live services; no explicit-allow-skips-URL-filtering cascade; no instance or tenant awareness |

## Work queue, second round (written after the first was finished)

| # | Requirement | Gap | State |
|---|---|---|---|
| G12 | ZIA-032, SMB-022 | Automatic exemption of pinned applications, banking and health from TLS inspection, with admin override | **done (S33)**; the built-in pinned list is small and unverified; banking and health depend on a category list the platform does not ship |
| G13 | NFR-023 | Administrator and vendor support access that is time-boxed (tokens that expire), logged and visible to the customer | **done (S34)**; permanent administrators still do not expire; no SSO or MFA |
| G14 | SMB-002 | Safe-defaults pack that also turns inspection on with the managed exemptions, refuses uploads to file-sharing apps and executables | **done (S35)**; inspection stays opt-in because devices must trust its CA first; only the anonymous sharing services are refused by default |
| G15 | NFR-024 | Reproducible, checksummed release build with an SBOM | **done (S36)**; no code-signing certificates, no notarisation, no installers; found and fixed: the agent did not compile for Windows |
| G16 | INT-006 | An OpenAPI description of every admin API route, generated from the route table | **done (S37)** for the description; no field schemas, no Terraform provider |
| G17 | NFR-030 | Data subject access and erasure: export what is held about a person, and delete it | **done (S38)** for the technical part; the legal part (a DPA, a public sub-processor list, a lawful basis) is not software and is not done |
| G18 | ADM-001 | Console simple mode (users, apps, alerts) | done: S39 |

## Third queue: gaps found when the requirements were reviewed again (v0.9, section 20)

These are written as proposals in REQUIREMENTS.md section 20. None is built. They need the product owner's yes on priority before design.

| # | Requirement | What is missing | State |
|---|---|---|---|
| G19 | GAP-REQ-01 | Backup and restore of the control plane with a restore test | proposed |
| G20 | GAP-REQ-02 | Secrets and private keys encrypted at rest | proposed |
| G21 | GAP-REQ-03 | Break-glass recovery when the last owner token is lost | proposed |
| G22 | GAP-REQ-04 | Rate limits and lockout on admin, enrolment and sign-in | proposed |
| G23 | GAP-REQ-05 | Key and certificate rotation and a compromise procedure | proposed |
| G24 | GAP-REQ-07 | "Person left" in one action with a checklist | done: S40 (first, in the order the product owner chose: 07, 01, 02, 05, then the rest) |
| G25 | GAP-REQ-06, 08, 09, 10, 11 | Clock accuracy, upgrades and version skew, console accessibility, IPv6, breach notification (should-level) | proposed |

## Not feasible without a new subsystem or an outside party (stays a gap)

- **Network and threat engines:** FW-001..003, FW-006 (IPS, Snort rules), FW-007 and ZIA-022a (DNS service), ZIA-020 (antivirus), ZIA-021, ZIA-023 (sandbox), ZIA-005 and ZIA-010 (cloud firewall and layered order), FW-011.
- **SaaS API scanning:** DATA-002 out-of-band CASB, DATA-004 prompt inspection beyond pattern DLP.
- **Platform and operations:** ARCH-001/003 (several active nodes in a hosted cloud, not just on-site nodes), NFR-000/001/003/010/011/040/041/050 (availability, latency, scale and maintenance targets need a hosted multi-node service and load measurement), NFR-021 (HSM or KMS), NFR-022 (penetration test, SOC 2), NFR-024 (signed reproducible builds and SBOM), NFR-030 (legal).
- **Agents and access models:** AGT-001a (VDI), AGT-001b/c (QUIC, MASQUE, WireGuard, all-ports tunnel, IPv6, FIPS), ARCH-011 (clientless portal), ARCH-010 beyond the current agent, ZIA-033 (managed trust of the CA through MDM).
- **Integrations that need accounts at other vendors:** INT-001 beyond generic OIDC (tested only with a test IdP), INT-003 (Intune, Jamf, CrowdStrike and others), INT-006 (Terraform provider).
- **Commercial and partner:** ADM-010 and SMB-020 (MSP multi-tenancy, white label, billing), OPS-001 and OPS-002 (managed service and detection), SMB-006 (a commercial policy), ZIA-016 (bandwidth control).

## Already recorded elsewhere

The 14 promoted Must items still unbuilt, and the usability work that needs people, are in STATUS.md and the exit review.
