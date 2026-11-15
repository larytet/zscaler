# Log streaming: what is sent, and how

A tenant can have the platform send its logs to its own log system (a SIEM). Set it up with the admin API
(needs the admin or owner role):

```
PUT    /v1/siem        {"kind":"https","url":"https://siem.example.com/ingest","header":"Authorization","token":"Bearer abc","ca_pem":"..."}
PUT    /v1/siem        {"kind":"syslog","addr":"siem.example.com:6514","proto":"tls","ca_pem":"..."}
GET    /v1/siem        what is set (never the token or the CA), and how it is doing
POST   /v1/siem/test   send one test event now and say whether the receiver took it
DELETE /v1/siem
```

`decisions` and `audit` (both default to true) choose what is sent. `ca_pem` is for a receiver whose certificate comes
from a private authority. `header` and `token` are for HTTPS: the token is the whole header value, for example
`Bearer abc` or `Splunk abc`. The token is write-only: no endpoint returns it, it is not in the audit log, and it is not
in an error message. (It is stored in clear in the control plane's data file, like the other secrets, so protect that file.)

## Transport

- **HTTPS:** a `POST` of newline-delimited JSON (`Content-Type: application/x-ndjson`), up to 100 events per request.
  A `2xx` answer means taken. `408`, `429`, `5xx` and network errors are retried with back-off (1 s doubling to 1 min),
  and the events stay queued. Any other answer (a wrong token, say) drops that batch and counts it as `failed`, so it
  cannot block what follows. Redirects are not followed.
- **Syslog:** RFC 5424 over TCP (one message per line), TLS (the same, verified against the system roots and `ca_pem`)
  or UDP (one message per datagram, so keep events small). Facility local0; severity warning (4) for a refusal, notice
  (5) for an audit event, informational (6) otherwise. App name `smbztx`; the message id is the event type; the message
  body is the JSON event below.
- **Delivery is at least once and in order per sink.** Events are queued in memory (10,000 per tenant); when the queue is
  full the oldest are dropped and counted (`dropped`). A restart of the control plane loses what was queued. The
  statistics (`sent`, `failed`, `dropped`, `queued`, `last_success`, `last_error`) are in `GET /v1/siem`.
- **What the control plane will not call:** the cloud metadata address and other link-local, unspecified and multicast
  addresses, loopback, and anything that resolves to them. Private addresses are allowed, because a SIEM often sits on
  the customer's own network. HTTPS only.

## Events

Every event is one JSON object with these fields, and then the fields of its type.

| Field | Meaning |
|---|---|
| `schema` | `smbztx.v1`. A change that removes or renames a field gets a new value |
| `type` | `decision`, `audit` or `test` |

### `decision`: a decision record from an enforcement node

| Field | Meaning |
|---|---|
| `ts` | Time of the decision (RFC 3339) |
| `tenant`, `kind` | Tenant id; `private` (private app), `web`, `connector` or `posture` |
| `event` | `open` when a session or request began, `close` when it ended (with byte counts) |
| `user`, `device` | Who, and from which device (`agent:name` for an AI agent) |
| `app`, `target` | The app segment, or the host and port reached |
| `action` | `allow`, `deny`, `warn`, `pass`, `fail`, `info` |
| `rule`, `reason` | The rule that decided and why (a plain sentence or a code such as `default`, `posture`, `approval-required`) |
| `ref` | On refusals and warnings: the reference the user saw on the page, so a person's report can be matched to the record |
| `policy_version` | Version of the policy that decided |
| `en` | Name of the enforcement node |
| `inspected`, `workspace` | Present when the request was decrypted, or came from the workspace browser |
| `dlp` | The data types found, when a data-protection rule acted (never the data) |
| `groups`, `posture` | The user's groups and the device's posture at the time of the decision |
| `bytes_up`, `bytes_down` | On `close` events |

With the tenant's privacy mode on (`PUT /v1/privacy`), `user` carries a stable pseudonym (`u-0123456789ab`) instead of the name, for events from that moment on; AI agents keep their names.

Never present: request or response content, URL paths and query strings, captured exchanges (the `capture` kind is
never streamed) and device health reports.

### `audit`: an administrator's action

| Field | Meaning |
|---|---|
| `seq`, `ts`, `tenant` | Position in the tenant's audit chain, time, tenant |
| `actor`, `action`, `object` | Who, what (`policy.put`, `user.disable`, `siem.put`, ...) and on what |
| `before`, `after` | The object before and after, where there is one (never a secret or a token) |
| `prev`, `hash` | The audit chain: each event's hash covers the previous one, so a gap or an edit can be found |

### `test`

`message` and `time`; sent by `POST /v1/siem/test`.

## Limits

Streaming starts when it is set up: nothing before that is sent (the decision records are also in the enforcement
node's own file, and the audit log in the control plane's). The control plane keeps no copy of what failed to be
delivered beyond the queue. There is no per-field filtering or masking, and no streaming of the live traffic itself.
