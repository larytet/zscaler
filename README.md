# SMB-ZTX

A small-business zero-trust platform, aimed at functional parity with the Zscaler Zero Trust Exchange for organisations of roughly 5 to 250 people with no security team. This repository holds the research, the specification, the design, the test plan and a first runnable build (RB1) in Go.

**RB1 is an evaluation build, not a product.** It proves the core loop: identity and device posture, then policy, then a brokered private connection or a filtered web request. It does not inspect TLS, has no DLP, no browser isolation and no installers. See [ROADMAP.md](ROADMAP.md) for everything left out, and [STATUS.md](STATUS.md) for what is done and what is broken or missing.

## Documents

| File | What it is |
|---|---|
| [USABILITY-RUNBOOK.md](USABILITY-RUNBOOK.md) | Script for the checks that need people (first-user time, alert clarity, workspace browser by hand) |
| [STATUS.md](STATUS.md) | Current progress, known gaps, open decisions. Updated after every subtask |
| [REQUIREMENTS.md](REQUIREMENTS.md) | The requirements (v0.5). Tagged `[V]` verified against a public source or `[I]` inferred |
| [DESIGN.md](DESIGN.md) | Software design for RB1 |
| [TEST-PLAN.md](TEST-PLAN.md) | Test plan for RB1 |
| [ROADMAP.md](ROADMAP.md) | Features deferred beyond RB1, including newly-Must items |
| [RESULTS.md](RESULTS.md) | Measured targets and misses |
| [COMPETITIVE-ANALYSIS.md](COMPETITIVE-ANALYSIS.md) | Cato Networks and Palo Alto Networks |
| `.doc/ZSCALER-IDEAS.md` | Low-hanging ideas for Zscaler. The source PDFs in `.doc/*/` are git-ignored |

## Layout

```
cmd/ztx-cp         control plane: admin API, enrolment, state sync, alerts
cmd/ztx-en         enforcement node: private-access broker and web proxy
cmd/ztx-connector  runs next to private apps; only dials out
cmd/ztx-agent      endpoint agent: OIDC login, posture, local SOCKS and HTTP proxies
internal/          policy, mux, pki, posture, idp, broker, webproxy, store, cp, en, agent, alerts, audit
test/idp           in-process OIDC provider for tests
test/e2e           end-to-end scenarios that start the real binaries
```

## Build and test

Needs Go 1.24 or newer.

```
make build     # binaries into bin/
make race      # unit and component tests with the race detector
make e2e       # end-to-end scenarios with the real binaries (about 30 s)
make fuzz      # 30 s per fuzz target
go test -tags perf -v -run TestPerf ./internal/broker   # performance targets
```

## Try it on one machine

These steps use loopback ports and a throwaway data directory. You need an OIDC identity provider that supports the authorization-code flow with PKCE and can put a `groups` claim in the ID token (Entra ID, Google Workspace with groups, Okta). Register a **public** client with redirect URI `http://127.0.0.1/callback` (loopback with any port). Replace `ISSUER` and `CLIENT_ID` below.

```
make build && cd bin

# 1. control plane
echo 'choose-a-long-random-string' > boot.token
./ztx-cp --data cp-data --bootstrap-token-file boot.token &
# cp-data/ca.pem is the trust root every other component needs

# 2. create a tenant (prints an admin token; keep it)
CA=cp-data/ca.pem; BOOT=$(cat boot.token)
curl --cacert $CA -s -X POST https://localhost:8443/v1/tenants \
  -H "Authorization: Bearer $BOOT" -d '{"id":"acme","name":"Acme"}'
export TOK=<admin_token from above>

# 3. identity provider, one private app, safe-default policies
curl --cacert $CA -s -X PUT https://localhost:8443/v1/idp -H "Authorization: Bearer $TOK" \
  -d '{"issuer":"ISSUER","client_id":"CLIENT_ID","group_claim":"groups"}'
curl --cacert $CA -s -X POST https://localhost:8443/v1/segments -H "Authorization: Bearer $TOK" \
  -d '{"id":"wiki","group":"office","class":"standard","targets":[{"host":"127.0.0.1","ports":[8000]}]}'
curl --cacert $CA -s -X POST https://localhost:8443/v1/policies/safe-defaults -H "Authorization: Bearer $TOK"
# the safe defaults let the IdP group "all-staff" reach standard apps from devices
# with disk encryption and the firewall on; web categories malware, phishing and
# command-and-control are blocked

# 4. enforcement node
curl --cacert $CA -s -X POST https://localhost:8443/v1/ens/tokens -H "Authorization: Bearer $BOOT" \
  -d '{"names":["localhost","127.0.0.1"]}'          # -> {"token": "..."}
echo '{"malware":["example-bad.test"]}' > categories.json
ZTX_EN_TOKEN=<token> ./ztx-en --cp-ca $CA --categories categories.json &

# 5. connector (next to the app)
curl --cacert $CA -s -X POST https://localhost:8443/v1/connectors/tokens \
  -H "Authorization: Bearer $TOK" -d '{"group":"office"}'
ZTX_CONNECTOR_TOKEN=<token> ./ztx-connector --cp-ca $CA --en 127.0.0.1:9443 --en-name localhost &
python3 -m http.server 8000 --bind 127.0.0.1 &       # the "private app"

# 6. agent (on the user's device)
mkdir -p ~/.ztx-agent && cat > ~/.ztx-agent/config.json <<EOF
{"tenant":"acme","issuer":"ISSUER","client_id":"CLIENT_ID","enrol_url":"https://localhost:8444",
 "enrol_ca_pem":"$(sed ':a;N;$!ba;s/\n/\\n/g' $CA)",
 "en_addrs":["127.0.0.1:9443"],"proxy_addrs":["127.0.0.1:9444"],"en_name":"localhost",
 "apps":{"wiki.ztx":"wiki"}}
EOF
./ztx-agent enrol        # opens the browser to sign in
./ztx-agent run &
curl --socks5-hostname 127.0.0.1:1080 http://wiki.ztx:8000/   # reaches the private app
curl -x http://127.0.0.1:3129 http://example-bad.test/        # 403 block page
curl -s http://127.0.0.1:9100/status                           # agent status
curl --cacert $CA -s https://localhost:8443/v1/alerts -H "Authorization: Bearer $TOK"
```

If the device fails the posture check (no disk encryption detected, or no firewall detected), the private app is denied and the decision log at `en-data/decisions.jsonl` says why. On Windows the firewall probe is not implemented, so posture-protected apps are denied there.

Fast reaction to a suspected compromise: `POST /v1/users/{id}/restrict` puts the user in a product-side `restricted` group. The safe-default policies deny it first, so live sessions end within seconds without waiting for your identity provider. `POST /v1/users/{id}/unrestrict` lifts it. If you wrote your own policy, add a deny rule for the group `restricted`.

Workspace browser (unmanaged devices): enrol it with `ztx-agent --dir ~/.ztx-workspace enrol-workspace`, then run `ztx-agent --dir ~/.ztx-workspace workspace [https://start.page]`. It starts Chrome, Chromium or Edge in a fresh isolated profile (no sync, no extensions, no QUIC) that reaches everything through the agent's local proxies, and locks itself (closes the browser, erases the profile) if the device is revoked, falls below the baseline (disk encryption and firewall) or loses the control plane for more than 5 minutes. Mark an app `"class": "sensitive"` and the safe defaults allow it only from the workspace. **Early.** Tested with real headless Chrome on Linux only. With inspection on, the workspace trusts the tenant's inspection key by a Chrome pin, in that browser only; a plain browser on the same proxy still shows certificate errors. Clipboard, download, upload and print controls do not exist yet (they need the workspace extension).

TLS inspection: `PUT /v1/inspection {"enabled": true, "exempt": ["bank.example"]}` decrypts HTTPS (except the exempt domains) so web rules can use `paths` and `methods`. Download the tenant's inspection certificate from `GET /v1/inspection/ca.pem` and install it on devices (system or browser trust store); until then inspected sites show certificate errors. Sites that refuse a replaced certificate go on the exempt list; the decision log records `inspection-handshake-failed` for them. It is off by default. No WebSockets or HTTP/2 through inspected tunnels.

Developer tools (needs inspection on): `eval "$(ztx-agent dev-env)"` points curl, git, pip, npm, Python, Go, AWS CLI and others at the proxy and at the tenant's inspection certificate (with the public roots kept). Java tools, Docker's daemon and certificate-pinning tools need manual steps; the command lists them.

Data loss prevention (needs inspection on): a web rule can carry `"dlp": ["credit-card", "us-ssn", "iban", "aws-access-key", "private-key", "github-token"]` and block uploads whose body contains any of them. Only the data type is logged, never the data. It is pattern based and basic, scans bodies up to 1 MiB and does not open archives or documents.

Just-in-time access: give a rule the action `require_approval` (it must name its apps). The first attempt is blocked and opens a request (emailed to the alert recipients when SMTP is set). Approve it with `POST /v1/approvals/{id}/approve {"minutes": 60}` or in the console; access starts within seconds and ends on its own, or earlier with `POST /v1/approvals/{id}/end`.

Redundancy: run two or more enforcement nodes, list them all in the connector's `--en` (comma separated) and in each agent's `en_addrs`. If a node dies, access continues through the others within seconds.

Device health and experience: `GET /v1/health` also gives each device an experience score (0 to 100) built from how long the agent took to connect and to open apps, with a one-sentence cause: device, network or app side. It shows each device's CPU load, memory and disk use as last reported by the agent (Linux agents only) with plain-language findings such as a nearly full disk.

AI agents: `POST /v1/ai-agents {"name":"code-helper","operator":"alice","apps":["erp"],"minutes":120}` creates a named identity run by a person, allowed only those apps for that long, and returns a one-time token for `ztx-agent enrol-service`. Add a `require_approval` rule for the group `ai-agent` (naming the apps) or the agent gets nothing. `DELETE /v1/ai-agents/{name}` ends it at once.

Risk: `GET /v1/risk` lists users with a 0 to 100 score and the reasons. A rule can use it with `"max_risk": 49` or `"min_risk": 70`. The safe defaults do not, so nothing is blocked on risk until you add such a rule.

Console: open `https://localhost:8443/` (the admin listener) and sign in with the admin token. It shows alerts, access decisions, people and devices, apps, a policy simulator, reports and an investigation page. It was walked through by hand in Chrome against sample data, but not on phones, other browsers or with assistive technology: report anything odd. To look at it without deploying anything, run `go run ./cmd/ztx-demo` (lab only: plain HTTP, loopback only, sample data in memory; it prints a token).

Alert emails: start `ztx-cp` with `--smtp-addr host:port --smtp-from alerts@yourdomain` (password in `ZTX_SMTP_PASSWORD`), then `PUT /v1/alert-settings` with `{"emails":["owner@yourdomain"]}`.

Weekly digest: `GET /v1/digest?days=7&format=text` returns the plain-language summary; with SMTP configured it is emailed to the same recipients every Monday 08:00 UTC. Search recent access decisions with `GET /v1/decisions?user=&app=&action=&since=`.

Try a rule change safely: `POST /v1/policies/private/simulate` with `{"policy": {...draft...}, "days": 7}` replays recent private-access decisions against the draft and lists who would be newly allowed or blocked. Nothing is stored.

Why was someone blocked? `GET /v1/investigate?user=alice` gives a plain-language timeline and the likely fix. `GET /v1/suggestions` proposes rules for repeated blocks (and flags unhealthy devices instead of widening access). Suggestions are drafts: simulate them first.

Insurance questionnaire evidence: `GET /v1/evidence?format=text`. It reports only what this product can show and marks everything else (MFA, EDR, backups) as not evidenced.

Secrets are read from files or environment variables and never from command-line arguments.

## Known limits that matter before real use

- TLS inspection is basic (see above) and off by default; there is no DLP or sandbox. With inspection off, web policy sees host names only.
- Posture is self-reported by the agent and can be forged by malware on the device.
- Certificates for connectors and enforcement nodes last 7 days and have no automatic renewal.
- Connector and enforcement-node state sync is a poll, not a push.
- Patent review of the connector stitching approach is needed before any commercial use (REQUIREMENTS.md section 15).
