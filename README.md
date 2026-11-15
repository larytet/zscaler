# SMB-ZTX

A small-business zero-trust platform, aimed at functional parity with the Zscaler Zero Trust Exchange for organisations of roughly 5 to 250 people with no security team. This repository holds the research, the specification, the design, the test plan and a first runnable build (RB1) in Go.

**RB1 is an evaluation build, not a product.** It proves the core loop: identity and device posture, then policy, then a brokered private connection or a filtered web request. It does not inspect TLS, has no DLP, no browser isolation and no installers. See [ROADMAP.md](ROADMAP.md) for everything left out, and [STATUS.md](STATUS.md) for what is done and what is broken or missing.

## Documents

| File | What it is |
|---|---|
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

Secrets are read from files or environment variables and never from command-line arguments.

## Known limits that matter before real use

- No TLS inspection, DLP or sandbox, so web policy sees host names only.
- Posture is self-reported by the agent and can be forged by malware on the device.
- Certificates for connectors and enforcement nodes last 7 days and have no automatic renewal.
- Connector and enforcement-node state sync is a poll, not a push.
- Patent review of the connector stitching approach is needed before any commercial use (REQUIREMENTS.md section 15).
