# Security

This document describes what VPNCheck Stand protects against, what it does not, and how to run it
safely. It covers the three parts: the stand (desktop program), the agent server and the Android agent.

## Reporting a vulnerability

Please do not open a public issue for security problems. Use GitHub's private vulnerability reporting:
the **Security** tab of this repository -> **Report a vulnerability**. Include the affected component
(stand, server or agent), the version or commit, and steps to reproduce. We will acknowledge the report,
work on a fix privately and credit you in the advisory unless you prefer otherwise.

## Threat model

| Who | Wants to | Through |
|---|---|---|
| Anyone on the network path (carrier, Wi-Fi owner, filtering equipment) | read or modify agent <-> server traffic | plain HTTP between agent and server |
| Someone who obtained the admin token | push their own nodes or files to agents, delete data | `/v1/admin/*` |
| Someone who obtained the update signing key | ship their own APK or core to every agent | the update manifest |
| A volunteer or anyone who knows the server address | use the published nodes as a free VPN | node credentials in `/v1/config` |
| Another app on a volunteer's phone | use the agent's test tunnel | local SOCKS port of xray |
| Anyone on the internet | overload the server, fill reports with junk | public endpoints |
| Anyone who can send a report | inject HTML/JS into the `/admin` page or the stand through agent fields (model, city, operator, node or site names) | report, error and result endpoints |
| Someone who shows a volunteer a forged pairing QR | move the agent to their server and signing key | the pairing QR code |
| Someone on the path to the DC probe | impersonate the probe server over SSH | the stand's SSH connection |

## What is in place

**Signed updates (the main protection).** The update manifest is signed with Ed25519. The private key
exists only on the stand PC (`%APPDATA%\VPNCheckStand\keys`); the public key reaches the agent through
the pairing QR code (or is built into the APK via `manifestPubKey`). The agent checks the signature and
the SHA-256 of every downloaded file and installs nothing without them. Rollback is blocked: the agent
remembers the `issued` time of the last applied manifest and rejects older ones. APK updates go through
the Android installer, which also requires the same APK signing certificate - another app with the same
package name cannot be installed over the agent. As a result, even full interception of HTTP traffic
does not allow code to be injected into agents.

**Pairing.** The QR code carries the server address and the public signing key. The agent shows the
server address and asks for confirmation before switching. If the agent already has a signing key and the
QR code carries a different one, the dialog shows an explicit warning that the update key will change and
that the volunteer should connect only if the owner of their server showed the code. The rollback guard
(`issued` time of the last manifest) is reset only when the server or the key actually changes. A link
without a key keeps the agent's current key (from an earlier pairing or built into the APK); an agent
that never had a key installs no updates. The server link is parsed strictly: only `scheme://host:port`
is accepted - no user name, path, query or fragment - and exactly that is shown in the dialog.

**Agent data is untrusted.** Everything an agent sends (phone model, city, region, operator, node keys,
site addresses, error texts) is treated as data, not markup: the `/admin` page escapes every value before
inserting it into HTML (including Yandex Maps hints), the stand's map escapes tooltips and hints, and the
stand's labels and tooltips with agent or phone data are shown as plain text. The stand passes data to its
map only as JSON (coordinates are checked to be finite numbers), and the map page is loaded from the
stand's own `vpncheck://assets/` scheme, so it has no access to files on the computer. The `/admin` page is served
with a `Content-Security-Policy` that allows scripts only from the server itself and Yandex Maps (no inline
scripts, no plugins, no framing, other resources only from the server itself and Yandex Maps). Uploaded
files under `/files/` are served with `Content-Security-Policy: sandbox`, so an HTML file there cannot run
scripts in the server's origin. Telegram alerts escape agent-supplied names for `parse_mode=HTML`.

**Server.**

- The admin token is compared in constant time (`hmac.compare_digest`); admin endpoints require the
  `X-Admin-Token` header.
- Public endpoints are rate limited per client IP (120 requests per minute - generous enough for carrier
  CGNAT); IPv6 clients are counted per /64 network. Stale rate windows are dropped, the table never resets
  as a whole.
- Request bodies are limited before they are read: a layer in front of the app checks `Content-Length`,
  cuts chunked bodies as soon as they pass the path's limit and answers 413 at once, so a large body
  never sits in memory or on disk. Admin paths without a valid `X-Admin-Token` get 401 before the body
  is read (an unauthenticated upload writes nothing to disk).
- Long-poll requests are capped per client address and in total (lower caps for unknown `agent_id`s,
  which get an answer at once); beyond the cap the server answers immediately. A long-poll request whose
  client has disconnected frees its place at once and does not keep the agent shown as online. uvicorn
  itself runs with `--limit-concurrency 5000` through `server/run.py`, which closes a connection that has not
  sent a complete request (headers and body) in 30 seconds, limits request headers to 64 KB and one address to
  256 connections (loopback excepted), and sets TCP keepalive 180/30/3 on every connection.
- Reports are limited to 256 KB and 500 nodes, strings are truncated, coordinates are range-checked,
  `agent_id` must be hex/hyphens. Only allowed fields are stored in the report history (versions, network
  and device fields, node and site results, location, check duration), each cleaned and truncated; the push
  token, error list and any unknown fields are not kept in reports.
- Besides the per-IP limit, writes are limited per agent and per address: 6 reports per minute per
  `agent_id` and 30 per IP network, other writes (errors, results, push tokens) 20 and 60 per minute.
  Per-agent limits and quotas are counted for the pair of `agent_id` and the sender's address, so someone
  who knows another agent's `agent_id` cannot use up that agent's limits from their own address.
- Results for nodes with `extra_outbounds` (chained outbounds) are ignored from agents older than
  versionCode 27 (0.11.0): older agents put only the main outbound into the config, so such a node would
  look dead to them.
- xhttp download channels (`downloadSettings`, directly in `xhttpSettings`/`splithttpSettings`, in their
  `extra` and nested) are checked by the same rule in three places - the server, the stand and the agent
  (shared cases in `tests/data/chain_cases.json`): a channel that goes through another outbound
  (`dialerProxy`, `proxySettings`) makes the node `unsupported`, because xray would loop into itself; the
  channel's address passes the same public-address check as the node's own address.
- Node configs are read the way xray reads them before any other check, again the same in the server, the
  stand and the agent. xray (Go `encoding/json`) matches field names without regard to case and with
  Unicode folding (the long s U+017F is `s`, the Kelvin sign U+212A is `k`) and takes the last of
  repeated keys, so `"DialerProxy"` or `"Address"` next to `"address"` would slip past checks written for
  the exact names. A
  node where a known xray field (address, port, settings, streamSettings, sockopt, dialerProxy,
  proxySettings, tag, xhttpSettings, extra, downloadSettings, tlsSettings, echConfigList, protocol and
  others) is spelled differently, or where two keys of one object are the same for xray, is
  `unsupported`; a subscription or node JSON with a repeated key in one object is treated the same way.
- `tlsSettings.echConfigList` is accepted only as a ready ECH config (base64). A value with a server
  (`name+https://...`, `udp://...`) makes the node `rejected`: xray would fetch the ECH record from that
  server directly, including one in a private network.
- Since agent 0.12.4 the server, the stand and the agent also share these rules (cases in
  `tests/data/chain_cases.json`). A `freedom` outbound in a chain may only have the `settings` fields
  `domainStrategy`, `fragment`, `noises`, `userLevel` and `redirect` (names matched with the same folding);
  any other field makes the node `unsupported`, and a non-empty `redirect` makes it `rejected`.
  `sockopt.addressPortStrategy` (in the main outbound, in chained outbounds and in download channels) is
  accepted only when it is missing, `null` or `"none"` in any case; any other value, including `""`, makes
  the node `unsupported`, because xray would look up the address and port in DNS (SRV/TXT) outside the
  pinned addresses. Keys inside a `headers` object (the object itself found with folding) are HTTP header
  names chosen by the node owner: they are not checked for folding, repeats or guarded names. A download
  channel of an outbound that goes out through another one (`proxySettings` with `transportLayer`) is still
  dialed from the phone, so its address is checked and pinned like the node's own address.
- Since agent 0.12.7 node fields are checked against an allow list, not a block list: `stand/node_fields.json`
  (read by the stand and the server, copied into the agent as `NodeFields.kt` with a test that both match)
  lists every field allowed in an outbound, in the `settings` of each supported protocol, in `streamSettings`
  and the transport settings, xhttp `extra` and `downloadSettings`, `sockopt`, `tlsSettings` and
  `realitySettings`. Any other field (names matched with the same folding) makes the node `unsupported`, so a
  new xray feature that dials its own addresses is closed until it is reviewed; this already covers
  `finalmask` (realm, xdns, xicmp), `masterKeyLog`, `certificates`, `echSockopt` and vless `reverse`.
  `sendThrough` and `sockopt.tproxy` (other than `"off"`) make the node `unsupported` too. An address that
  starts with `env:` or contains a whitespace or control character (including U+0085, which Go trims and
  Kotlin does not) makes the node `rejected`. Header maps keep arbitrary keys.
- Since agent 0.12.8 `mux` with `enabled` set is allowed only in the main outbound: in a chained outbound
  (a `freedom` link would send the node's traffic to `v1.mux.cool` instead of the node) it makes the node
  `unsupported`. So does a main outbound `tag` that is not a string, and nesting deeper than 64 levels. An
  address with an IPv6 zone (`%`) makes the node `rejected`. NaN, Infinity and numbers outside the float
  range are refused when the stand reads a subscription and when the server reads `/v1/admin/state` (400);
  stored nodes with such numbers are dropped when the server reads its state.
- Everything agents send is kept for a limited time and deleted automatically (at startup and once a
  day): reports, command results, alerts and node states after 90 days, error logs after 30 days and
  never more than 500 per agent and 20,000 in total, geo caches after 180 days, agents silent for a
  year together with their push tokens.
- Telegram alerts are raised only for nodes and sites that are published on the server and only by
  agents known for more than 24 hours. Witnesses of a place (region and operator) are counted by network
  (IPv4 /24, IPv6 /48) over the last 7 days, so many `agent_id`s from one address are still one witness;
  a place is confirmed with witnesses from at least two networks. Events wait in a queue of at most 5,000,
  of which places with a single witness may take at most 4,000: the rest is kept for confirmed places, so a
  flood of made-up places cannot push them out. A pending alert is cancelled by the opposite result only
  when that result comes from a different network; a pending alert whose place has changed back by the time
  the message goes out is dropped as no longer true. In a message confirmed places go first and agents take turns. The whole server sends at most
  20 alerts per hour (node account expiry warnings and "all agents at zero" bypass the limit); a message
  that was not delivered stays in the queue (up to 90 days). A message is cut to 3,900 characters with
  place names shortened, so agent-supplied names cannot push it past Telegram's 4,096 limit and block the
  queue; a message that Telegram refuses (400) is not retried: it gets an entry in the error log and its
  events are still written to the alert history marked as not delivered, and only delivered messages count
  toward the hourly limit. Events left out of a cut message are written to the history too. An event
  that falls into the 6-hour repeat interval waits until the interval is over instead of being dropped.
  The 6-hour repeat interval for a whole node is set only by an alert from a confirmed place, so a made-up
  place with a single witness cannot silence real "down" alerts through it. A node that changes its state 5
  times a day in a place while being up in 20-80% of the checks there is paused for at least a day in that
  place only; the "works on and off" message is sent only for a confirmed place. "Responding again" for a
  node that is still down elsewhere comes at most once in 3 hours. "All agents at zero" counts agents by
  the network of their last report (IPv4 /24, IPv6 /48), not by `agent_id`, and needs at least 3 networks. Alerts are sent from a background thread with
  retries, not from the request handler.
- Push tokens are accepted only from agents that already send reports (or together with the first
  report); an existing token can be replaced only from the IP address it was sent from, or after the
  phone has not confirmed it for 24 hours; the table is capped at 5,000 tokens (when it is full, the
  oldest token of an agent known for less than 24 hours gives way, otherwise a new token is refused).
  Tokens that Firebase rejects as unregistered or invalid are deleted, and pushes are sent in parallel
  in the background.
- Uploads require the admin token, file names use a safe alphabet, size is limited to 120 MB, files are
  written via a temporary `.part` file. `/files/` and `/static/` serve only safe names, path traversal is
  not possible.
- The IP-echo and latency URLs pushed to agents must be `https://`.
- All SQL queries are parameterized.
- The installer (`server/install.sh`, also used by `server/deploy.py`) runs the service as its own system
  user `vpnagent`, not root. The code and the Python venv in `/opt/vpnagent` belong to root (the folder is
  `root:vpnagent`, mode 750), so the service cannot change its own code or the venv that root runs `pip`
  from on the next install. The data (database, settings pushed from the stand, backups, uploaded files,
  the Firebase service account) lives in `/opt/vpnagent/data`, owned by `vpnagent` with mode 700; the
  unit passes it as `VPNAGENT_DATA` and allows writes only there (`ProtectSystem=strict`,
  `ReadWritePaths=/opt/vpnagent/data`). The unit also sets `UMask=0077`, `NoNewPrivileges`, `PrivateTmp`,
  `PrivateDevices`, `ProtectHome`, `ProtectKernelTunables`, `ProtectKernelModules`,
  `ProtectControlGroups`, `LockPersonality`, an empty `CapabilityBoundingSet` and
  `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`. The `env` file with the admin token and Telegram
  settings and the `admin_token` file are root-only (600) and are written through temporary files in the
  root-owned folder; the installer refuses to run if they are symbolic links. An older install with
  everything in `/opt/vpnagent` owned by `vpnagent` is converted on the next run: the service is stopped,
  the data is moved to `data/`, the old code and venv are deleted and installed afresh, and anything
  unknown is moved to `data/old-install/` instead of staying next to the code. The installer stops the
  service before it reads or changes anything in `/opt/vpnagent`, so the service user cannot race it.
  During the conversion the folder is made root-only first; a `data/` folder that the service user
  created is set aside whole into `data/old-install/data` and never written through; items are moved one
  by one with `mv -T` into a freshly created `data/`, and symbolic links in the moved data are deleted.
  Data files left next to the code by an interrupted conversion are picked up on every run. From the old
  `env` file only known settings are kept (the installer's own, `VPNAGENT_*` and proxy variables);
  anything else, such as `LD_PRELOAD` or `PYTHONPATH`, is dropped with a warning. The Firebase service
  account is written with its owner and mode in one step. If the installer fails before the conversion,
  it starts the service again.
- `server/deploy.py` passes the admin token and Telegram settings to the installer in a file with mode
  600 inside a private temporary folder (`ENV_FILE`), which the installer deletes after reading; secrets
  never appear on a command line, in `ps` output or in the sudo log.
- `BEHIND_PROXY=1` (or `deploy.py --behind-proxy`) makes the service listen on 127.0.0.1 only.
- Agent commands are a fixed list (check, update, locate, message, diagnostics, site check, xray log,
  speed test, whitelist check). There is no way to run arbitrary code on a volunteer's phone.

**Agent.**

- The local SOCKS port of xray is protected by a random username and password for each test, so other
  apps on the phone cannot use the tunnel.
- Configs and downloaded files are kept in the app's private storage; `allowBackup` is off.
- The agent's own connections refuse private and local addresses (loopback, 10/8, 172.16/12,
  192.168/16, 100.64/10, link-local, IPv6 ULA/link-local, `localhost`) at the socket level - for IP
  literals, after DNS resolution and on every redirect. This covers site checks (scheduled and the
  `site_check` command) and the IP-echo and latency URLs, which must also be `https://`. So the server
  cannot use a phone to probe the volunteer's home network.
- Node configs are limited to tunnel protocols (VLESS, VMess, Trojan, Shadowsocks, Hysteria/Hysteria2);
  `freedom`, `blackhole`, `dns` and redirect outbounds from the server are dropped, nodes with a private
  address are rejected, and inside xray all private networks are routed to `blackhole`. Since 0.12.1 the
  agent resolves node domain names itself before the test: a name that resolves to a private address is
  rejected, and the addresses found are pinned in the test config (`dns.hosts` plus `ForceIP`, which
  replaces the node's own `domainStrategy` in `sockopt`, in download channels and in `freedom`), so xray
  connects exactly to the checked addresses and never falls back to the system DNS. A DNS lookup that
  times out leaves the node unchecked instead of marking it dead.
- Since 0.12.5 every connection xray makes for a test (the node, chained outbounds that dial directly and
  download channels) is bound to the network interface being checked (`sockopt.interface`,
  `SO_BINDTODEVICE`); an `interface` field that the node sets itself is replaced. So a check of mobile
  data really goes over mobile data when Wi-Fi is on, and a node cannot pick another interface.
- Downloaded updates are limited to 150 MB.
- Location is optional. Approximate location is taken only while the app is open and is rounded to the
  precision set in the control center. A precise one-time location is requested only on an explicit
  command from the control center and only if the volunteer granted precise location. See the privacy
  section of the [README](README.md#agent-privacy) for the full list of what is sent.

**Node account for agents.** Nodes published for agents come from a separate panel user (prefix
`vpnagent`) with a 500 MB traffic limit and a 30-day lifetime, created by the stand. Anyone who
extracts the node list from the server or the app gets at most that much traffic until the account
expires. Temporary users that the stand creates for its own runs are deleted after the run.

**Stand.** Secrets are stored outside the program folder in `%APPDATA%\VPNCheckStand`:
`connections.json` (Remnawave panel URLs and API tokens, DC probe SSH access), `agent.json` (agent
server address and admin token) and `keys/` (update signing key). SSH to the DC probe (also used by
`server/deploy.py`) is trust-on-first-use: the server's host key is remembered in `connections.json`
(`probe.host_key`) on the first login, and later logins with a different key are refused with an explicit
error. If the server was reinstalled, clear the probe address in **Connections**, save and enter it again.
On the probe server the stand runs its helper scripts by piping them to `python3 -` (base64 over SSH) and
quotes every value it puts into a shell command; it does not leave scripts under predictable names in
`/tmp`, and the Xray core is checked against its SHA-256 before use. Keystore files,
`keystore.properties`, `google-services.json` and the Firebase service account are excluded by
`.gitignore`.

## Known limitations

1. **Plain HTTP is allowed.** The agent's `network_security_config.xml` permits cleartext traffic to any
   host, because the server address is set by the pairing QR code and may be a bare IP without TLS. Over
   HTTP an on-path observer can read reports (carrier, node results, phone model, approximate location)
   and replace the node list - then the volunteer's phone makes test connections to someone else's
   servers. Code cannot be injected (see signed updates), but you should put the server behind HTTPS.
2. **The admin token travels in the clear over HTTP** from the stand and from the `/admin` page (where it
   is kept in the browser's localStorage). Same answer: HTTPS. The token can be rotated at any time: run
   `sudo ADMIN_TOKEN=<new value> bash server/install.sh` (or change it in `agent.json` and re-run
   `server/deploy.py`), then enter the new value in the stand. Without `ADMIN_TOKEN` the installer keeps
   the token the service runs with (from `/opt/vpnagent/env`) and warns if `/opt/vpnagent/admin_token`
   differs from it.
3. **The node list is public to anyone who knows the server address.** `/v1/config` needs no token,
   because agents have no individual credentials. This is why the agent node account is limited in
   traffic and time.
4. **Reports can be spoofed.** Anyone who knows the format can send reports with a made-up `agent_id`.
   What limits the damage: results are stored only for nodes and sites published on the server (other
   keys are dropped); a single IP address (or IPv6 /48) can introduce at most 20 new `agent_id`s per day;
   error logs are capped when they are written, not only by the daily cleanup; each agent keeps at most
   5,000 reports, and when there are more, reports from the address the new one came from are deleted
   first, so a flood under someone else's `agent_id` from another address erases its own reports, not the
   real agent's history; when the database reaches its size limit, reports are evicted instead of refusing
   everyone or filling the disk - first those of agents known for less than 24 hours, then the oldest
   reports across the whole database, at most a tenth of one agent's reports per pass, so neither a flood of
   junk nor one busy agent wipes the history of long-known agents; each agent has a daily quota of 300 reports (100 for agents known for less than 24 hours), and
   one address (IPv6 /48) at most 500 reports per day across all `agent_id`s; the node x region matrix
   and the trends are computed only from agents known for more than 24 hours and are aggregated and
   limited on the server side; new agents do not raise Telegram alerts for 24 hours. A fake "region" on
   the map is still possible, and many addresses together can still add noise to the statistics. Such
   data is shown as text, never executed (see "Agent data is untrusted").
5. **Rate limiting and `X-Forwarded-For`.** The server trusts this header only when the request comes
   from a reverse proxy on the same machine (127.0.0.1 or ::1) and takes the last address in it; a client
   connecting directly cannot bypass the per-IP limit by setting the header. A proxy on another machine is
   not trusted - every request would then count against the proxy's address. Behind a reverse proxy,
   close the server's own port to the outside (see below).
6. **The signing key is not encrypted on disk.** Anyone with access to the stand PC can sign a malicious
   manifest. Changing the key means reconnecting every agent by QR - old agents will not accept a new key
   on their own.
7. **Third-party services.** The server resolves agent IPs via ipinfo.io and coordinates via OpenStreetMap
   Nominatim; the stand resolves node IPs via ipinfo.io. The agent uses the IP-echo and latency URLs you
   configure (defaults: api.ipify.org and google.com/generate_204), speed.cloudflare.com for the speed
   test and neverssl.com for the whitelist check. The server installer asks api.ipify.org once for the
   server's public address to print it; when Telegram alerts are set, it also sends one test message
   through api.telegram.org (the bot token goes to `curl` through standard input, not the command line).
8. **Agents have no credentials of their own.** Commands for an agent (`/v1/poll`) are handed to anyone who
   knows its `agent_id`: the text of a message, the URL of a site check, the node key for an xray log. Keep
   secrets out of messages.

## Recommendations

**Put TLS in front of the agent server.** Point a domain at the server and run a reverse proxy on the same
machine. With Caddy (certificates are obtained automatically):

```
agents.example.com {
    reverse_proxy 127.0.0.1:8787
}
```

With nginx, overwrite the forwarded header instead of appending to it:

```nginx
location / {
    proxy_pass http://127.0.0.1:8787;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_read_timeout 300s;  # agents keep a long-poll request open for up to 4 minutes
}
```

Then make the agent server listen on 127.0.0.1 only: `sudo BEHIND_PROXY=1 bash server/install.sh` (or
`python server/deploy.py --behind-proxy`). Port 8787 is then closed to the outside whether or not a
firewall is active; the installer also removes its ufw rule. Use `https://agents.example.com` in the
control center, and pair agents again so they get the HTTPS address.

**Protect the update signing key.** Keep a backup outside the PC (offline media), protect the PC with a
password and disk encryption, and never commit the `keys/` folder.

**Keep the server TLS key.** Agents 0.12.9+ pin the key in `/opt/vpnagent/tls` (`cert.pem` + `key.pem`):
copy the folder off the server together with the database. A new key cuts agents 0.12.9-0.12.10 off until
the app is reinstalled; 0.12.11+ recover only through a newer manifest signed with the update key. The
installer never replaces an existing key unless `VPNAGENT_TLS_REGENERATE=1` is set.

**Use your own APK signing keystore** (`agent/keystore.properties`). The Android debug key is not meant
for distribution: it is unprotected and differs from machine to machine, and Android only updates an
installed agent with an APK signed by the same certificate. Keep the keystore and its passwords backed up.

**Keep the Firebase service account on the server only.** `server/service-account.json` allows sending
push messages to all agents; the installer copies it to `/opt/vpnagent/data` with mode 600, readable
only by the service user (`deploy.py` uploads it into a private temporary folder first). Push messages carry only a command
name - all content is still fetched from your server and checked against the signature.
`google-services.json` in the APK contains public project identifiers and is not a secret.

**Rotate secrets on suspicion:** the admin token, Remnawave API tokens (in the panel), and the agent node
account (publish nodes again - a new account is created).

**Give the Remnawave API token only the rights it needs** (users and squads) and keep TLS verification
on in **Connections** unless you know why you need it off.
