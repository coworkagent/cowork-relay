# Cowork Relay

[简体中文](README.zh-CN.md)

`cowork-relay` is a self-hosted service that connects Cowork phones and computers
across networks. Computers make outbound connections; their LAN ports do not
need to be exposed to the internet. One instance supports several computers and
phones, with independent credentials and a specific computer assigned to each
client registration.

This is a development candidate. The service and its CLI are implemented;
integration into the desktop and mobile applications is still in progress.
Existing released applications cannot use this relay simply by entering its URL.
No binary or container image has been published.

## Security and compatibility

- Public access requires TLS 1.3. Use an HTTPS domain with a valid certificate,
  or an IP address with an automatically generated private CA and IP certificate.
  IP clients must import the public CA into application-scoped trust and verify
  the IP in the certificate. Disabling certificate verification is unsupported.
- Phone-to-computer TLS runs **inside** the relay connection. The relay forwards
  encrypted bytes; business credentials, messages, files and grants stay with
  the paired endpoints. The relay can observe source IPs, device IDs, timing and
  byte counts, and can interrupt traffic.
- Each client credential authorizes exactly one computer in one group. Device
  secrets are random 256-bit values; the registry stores hashes. Registration
  files contain secrets and must be transferred privately to their intended app.
- Administration uses a local Unix socket in a `0700` directory, with socket and
  state files restricted to `0600`. There is no public administration API.
- This service does not provide general web proxying, SOCKS, arbitrary CONNECT
  targets, Agent execution or project authorization. The computer still checks
  pairing, permissions and every business request.

The service targets Linux; native macOS execution is useful for development.
Native Windows service administration is not implemented. A reachable server IP,
an allowed inbound TCP port and outbound connectivity from both endpoints are
required. An IP behind carrier NAT without inbound forwarding is insufficient.
This version runs as one process per state directory; replicas do not share an
online device registry. Do not put it behind a normal HTTP reverse proxy. Use a
direct TLS listener or a TCP pass-through load balancer.

## Build and check

Install the Rust toolchain in `rust-toolchain.toml`, then:

```sh
cargo build --release --locked
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
npm ci
npm run test:acceptance
```

The last check needs Node.js 22.12+ and OpenSSL. Its synthetic connections bind
only loopback. Rust production code does not require Node.js or OpenSSL.
The binary is `target/release/cowork-relay`.

## Initialize an IP server

Replace `203.0.113.10` with the reachable address of your server. The public port
may differ from the listen port when your firewall forwards it.

```sh
umask 077
cowork-relay --data-dir ./relay-state init-ip \
  --ip 203.0.113.10 --port 8443 --listen 0.0.0.0:8443
cowork-relay --data-dir ./relay-state trust-export --out ./relay-trust.json
cowork-relay --data-dir ./relay-state serve
```

Initialization requires a new, empty private directory and never replaces an
existing identity. The listener defaults to `127.0.0.1:8443` unless explicitly
changed. `relay-trust.json` contains only the origin, public CA and its SHA-256
fingerprint. Verify the fingerprint through a trusted channel before importing
it. Importing a CA read from an unverified network connection does not establish
server identity. Do not distribute `ca-key.pem` or any server private key.

## Initialize a domain server

Obtain a certificate from a CA trusted by your clients, including its full chain.
The private key must have mode `0600` and be readable by the service account.

```sh
cowork-relay --data-dir ./relay-state init-domain \
  --origin https://relay.example.com:8443 --listen 0.0.0.0:8443 \
  --certificate /absolute/path/fullchain.pem \
  --private-key /absolute/path/privkey.pem
cowork-relay --data-dir ./relay-state serve
```

The relay checks certificate validity, SAN and key matching. Clients must also
validate the certificate chain using their platform trust store. Supplying an
untrusted certificate to `init-domain` does not make it trusted by clients.

## Manage devices

Run these commands on the server, as its service account, while it is running.
Keep the same `--data-dir`. `--json` produces structured output; `--lang zh-CN`
selects Chinese output. Help includes both languages.

```sh
cowork-relay --data-dir ./relay-state devices add-host \
  --name workstation --group personal --credential-out ./computer.json
cowork-relay --data-dir ./relay-state devices add-client \
  --name phone --group personal --host HOST_DEVICE_ID \
  --credential-out ./phone.json
cowork-relay --data-dir ./relay-state status
cowork-relay --data-dir ./relay-state devices list
cowork-relay --data-dir ./relay-state devices inspect DEVICE_ID
cowork-relay --data-dir ./relay-state connections
cowork-relay --data-dir ./relay-state devices kick DEVICE_ID
cowork-relay --data-dir ./relay-state devices disable DEVICE_ID
cowork-relay --data-dir ./relay-state devices enable DEVICE_ID
```

Registration returns a public device ID on stdout and writes its secret only to
the newly created `0600` credential file. Files are never overwritten. Transfer
each credential file privately to the matching endpoint and remove unnecessary
server-side copies. Do not paste credentials into command arguments or logs.
The default lifetime is 30 days; `--days` allows 1–90 days. There is no automatic
renewal of device credentials in this version. Re-enroll before expiry; a new
host registration requires new client registrations targeting its ID.

| Command | Effect |
| --- | --- |
| `kick` | Disconnect current control/data connections and cancel pending tickets; the credential can reconnect. |
| `disable` | Persist the disabled state, disconnect and reject future access, including after restart. |
| `enable` | Permit the same credential again if it has not expired. |

Disabling or kicking a computer disconnects its relayed client streams. Neither
action revokes LAN pairing or cancels an Agent task already accepted by the
computer. Revoke business access on the computer when that is the intended action.

## Capacity, certificates and operations

`config.json` contains bounded capacity settings. Defaults are 512 open network
sockets, 128 online computers, 256 streams in total, 32 streams per computer and
8 per client. Each active data stream consumes a phone socket and a computer
socket; the total socket limit also includes control connections. Admission is
additionally limited to 64 concurrent TLS/HTTP handshakes. Change settings while
stopped and restart. The CLI is local administration, not a persistent audit log.

Data messages are bounded to 64 KiB. Idle streams close after 90 seconds and all
streams reconnect after at most one hour. Clients must reconcile command status
after reconnecting rather than blindly replaying uncertain mutations.

Generated leaf certificates last one year; the private CA lasts ten years. To
renew a leaf under the same CA, stop the service, run the following command and
restart. Renewal requires `ca-key.pem`; keep an encrypted offline backup. The
public CA fingerprint is unchanged, so its imported trust remains valid.

```sh
cowork-relay --data-dir ./relay-state renew-ip
```

Renewal writes a fresh key and certificate, then atomically selects them. Previous
certificate files remain in the private directory for operator-managed cleanup.
For domain certificates, renew using your certificate provider and restart the
service. If the CA is compromised, expired or the server IP changes, provision a
new identity and explicitly distribute and verify its new trust material.
Back up the private state securely; restoring an old device registry can undo
later revocations. Avoid copying a live registry into a second running service.

`GET /health/live` returns process health over verified HTTPS without exposing
device data. TLS keys and configuration are read at startup. SIGINT/SIGTERM closes
connections; clients may reconnect once the service returns.

Container and systemd templates are in [deploy](deploy/). Review paths and network
settings before use. No public deployment is performed by these examples.
