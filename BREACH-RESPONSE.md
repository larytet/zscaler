# If the platform loses someone's data: first 72 hours

**This is a working procedure, not legal advice.** Whether an incident is a notifiable personal-data breach, who is the controller and who the processor, and what you must tell whom, are questions for your counsel and your data protection officer. Have them read this before you need it. It has not been rehearsed with a real incident.

It assumes the platform is run by someone (a small business, an IT provider, a vendor) who looks after the data of one or more **tenants**. If you run it only for yourself, you are both the operator and the only tenant.

## Contacts to fill in now, not during an incident

| Role | Name | Address and phone |
|---|---|---|
| Person who decides (operator) | | |
| Second person if the first is away | | |
| Counsel or data protection officer | | |
| Supervisory authority's breach notification form or address | | |
| Hosting or cloud provider's security contact | | |

Each tenant states its own security contact: `PUT /v1/security-contact {"name": "...", "email": "..."}` (an owner). If a tenant has none, the report below falls back to its alert recipients, and says so when there are none either. **Ask every tenant to set one now.**

## The clock

Write down, at once and on paper, **the time you became aware** that data may have been lost. A supervisory authority is to be told **within 72 hours of becoming aware** where the breach is likely to put people at risk (GDPR Article 33); a processor is to tell the controller **without undue delay** (Article 33(2)). Other laws and contracts have their own periods. Counsel decides which apply.

## Hour 0 to 2: stop it getting worse, and keep the evidence

1. **Do not wipe or rebuild anything yet.** Take a copy first: `ztx-cp backup -data cp-data -file /safe/place/evidence.tgz` (it can run while the control plane is up), then `ztx-cp verify-backup -file ...`. Keep it as carefully as the keys: it holds them.
2. Check the audit chain is intact (the report in step 4 does this). A broken chain means the log was altered: say so in your notes.
3. **Contain, by what was lost** (README, "If a key leaked", has the commands):
   * an administrator's token: `POST /v1/admins/{name}/rotate`, or remove the account;
   * the control plane's disk, a backup, or the running server: replace every administrator token, the SCIM token and the master key, rotate the TLS inspection CA, change every stored credential at the service it belongs to, and, if the CA key may have been taken, follow step 6 of that section;
   * an enforcement node: remove it from service, rotate the inspection CA of the tenants it served, and re-enrol a clean node.
4. If you can, note what was running when you found out: the program versions (`GET /v1/versions`), the server's address, who had access.

## Hour 2 to 8: find out who is affected

Run, on the control plane's server (it reads the data directory and changes nothing):

```sh
ztx-cp incident-report -data cp-data -aware 2026-11-15T09:30:00Z                       # the server, its disk or a backup was reached
ztx-cp incident-report -data cp-data -scenario node:en1 -aware ...                     # an enforcement node
ztx-cp incident-report -data cp-data -scenario admin-token:acme -aware ...             # one tenant's administrator token
# add -master-key-file KEY if the data is encrypted, -from/-to to choose the window, -json to feed another tool
```

It lists, for each tenant: whether it is in scope and why, **who to tell**, **what kinds of data are held and how many**, the days of decision records on disk, and the administrator actions in the window. It also prints the 72-hour deadline from the time you gave.

**What it cannot tell you, and no tool here can:** whether anything was **read**. The audit log holds changes made by administrators and the decision records hold access decisions; nothing records reads. Work on the assumption that everything listed for an in-scope tenant was exposed, and say so honestly in your notification if you cannot show otherwise. It also cannot see your identity provider, your log system, other copies of backups, the nodes' own files, or the connectors' and agents' machines.

## Hour 8 to 48: tell people

**Tenants first** (if you are a processor), by e-mail to the security contact, and by phone for a large incident. Say plainly:

1. What happened and when you became aware (facts only; mark what you do not know yet).
2. What kinds of their data were held, and roughly how many people and records (the report's numbers), and that **reads cannot be ruled out**.
3. What you have done (the containment above) and what they must do (for example: change credentials that were stored for injection; remove the old inspection certificate from devices; check their identity provider's sign-in log).
4. Who to contact at your end, and when you will write again.

**The authority**, if counsel says it is required, with the elements Article 33(3) lists: the nature of the breach including the categories and approximate numbers of people and records; the contact point; the likely consequences; the measures taken or proposed. You may give the information in phases if you cannot yet give it all, but give what you have inside the period.

**The people concerned** (end users of a tenant) are told by the controller, which is normally the tenant, if the risk to them is high. The report's "people" count is the list of whom it may concern.

A short template for the first message to a tenant:

> Subject: Security incident at <operator>: your data may be affected
>
> On <date, time, zone> we became aware that <what, in plain words>. We believe it affected <what was lost>. Your organisation (<tenant>) is in scope because <the report's reason>.
> The platform holds, for your organisation: <the report's list, with numbers>. We cannot show that any of it was read, so please treat it as exposed.
> We have <containment done>. Please <actions for the tenant>.
> We will write again by <time>. Contact: <name, phone, address>.

## After

Write down what happened, what the report said, what you told whom and when, and what you changed. Keep the evidence copy for as long as counsel says. Rehearse this once a year on a test installation: a rehearsal finds the missing phone number faster than an incident does.

## What this product does and does not give you

* Gives: a per-tenant security contact, a per-tenant list of what is held and how much, a way to scope a lost server, node or token, an audit chain that shows if it was altered, a backup tool for the evidence, key and token replacement, and this procedure.
* Does not give: a record of reads, notification e-mails sent for you (nothing is sent automatically, on purpose: a person decides), a legal opinion, a public sub-processor list or a data processing agreement (see STATUS.md, S38), or monitoring that would tell you a breach happened (only the weekly summary's "owner reset from the server" line and the lockout count on `GET /v1/keys` are hints).
