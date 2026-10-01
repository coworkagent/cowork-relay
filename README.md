# Cowork Relay

[简体中文](README.zh-CN.md)

`cowork-relay` is a self-hosted service that connects Cowork phones and computers
across networks. Computers make outbound connections; their LAN ports do not
need to be exposed to the internet. One instance supports several computers and
phones, with independent credentials and a specific computer assigned to each
client registration.

Version **0.2.0** adds automatic registration and certificate renewal, plus
bounded rejection logs, to the relay service and local administration CLI.
Use relay-capable Cowork desktop and mobile clients. The desktop integration
requires a matching remote component; desktop 0.15.0 and older cannot use the
relay simply by entering its URL. A mobile update alone does not update the
computer. Local and simulator checks do not qualify a real public deployment.
Container images are built locally from the included Dockerfile.

## Download and install

Download an archive and `SHA256SUMS` from the
[0.2.0 release](https://github.com/coworkagent/cowork-relay/releases/tag/v0.2.0).

| Platform | Archive | Requirements |
| --- | --- | --- |
| Linux x64 | `cowork-relay-0.2.0-linux-x64.tar.gz` | Static musl; no system libc dependency |
| Linux ARM64 | `cowork-relay-0.2.0-linux-arm64.tar.gz` | Static musl; no system libc dependency |
| macOS Intel | `cowork-relay-0.2.0-darwin-x64.tar.gz` | macOS 12+ |
| macOS Apple Silicon | `cowork-relay-0.2.0-darwin-arm64.tar.gz` | macOS 12+ |

Choose the archive for the server's architecture. From 0.1.1, Linux downloads
use statically linked musl and run on both glibc and musl distributions. No libc
upgrade or separate musl installation is required. The older 0.1.0 downloads
remain dynamically linked to glibc and do not have this compatibility fix.
CI tests the release binary on native Ubuntu 24.04 runners and additionally
checks startup and local administration in Ubuntu 20.04 and Alpine 3.22 userlands.
Containers share the runner kernel; this does not certify every older kernel.
Mac binaries are development utilities, without Developer ID notarization.
Native Windows binaries are not provided because local administration requires
Unix sockets and Unix file permissions; use a Linux server or Linux VM.

```sh
# Verify on Linux (on macOS, run shasum -a 256 on the archive and compare its entry).
sha256sum --ignore-missing -c SHA256SUMS
tar -xzf cowork-relay-0.2.0-linux-x64.tar.gz
mkdir -p "$HOME/.local/bin"
install -m 0755 cowork-relay-0.2.0-linux-x64/cowork-relay "$HOME/.local/bin/cowork-relay"
"$HOME/.local/bin/cowork-relay" --version
```

The archive includes both language guides and deployment templates. Keep the
state directory outside the extracted installation directory. Verify a checksum
from the authenticated release source; a checksum alone does not establish
publisher identity. For upgrades, stop the service, back up private state and
replace only the executable. Do not initialize the existing state again.

## Connect a computer and phone

1. Initialize the relay with one of the trust modes below and start it.
2. Create a host registration and a phone registration targeting that host.
   Privately deliver `computer.json` and `phone.json` to their intended devices.
3. In the computer's Remote control settings, import its registration, verify
   the relay address and CA fingerprint, then enable internet connections.
4. On the phone, import its relay registration and confirm the same server's
   identity. Trust is scoped to this relay, not installed system-wide.
5. Generate an internet pairing invitation on the computer, granting only the
   required projects/actions and internet access. Scan or import it on the phone,
   compare the six-digit code on both devices, and approve on the computer.

Supported relay clients require iOS 17+ or Android 10+; earlier supported app
versions retain LAN connectivity. Each phone registration targets one computer;
import additional registrations to connect to other computers. Available LAN
routes take priority. Changing the paired computer's identity requires explicit
pairing again; signed leaf renewal under the same saved CA can recover safely.

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
The binary is `target/release/cowork-relay`. A default Linux source build uses
the host libc; it is not the portable release build.

On a native Ubuntu/Debian machine of the desired architecture, install
`musl-tools`, add `x86_64-unknown-linux-musl` or `aarch64-unknown-linux-musl`
with `rustup target add`, and build with `CC=musl-gcc cargo build --release
--locked --target TARGET`. Set the matching Cargo target linker to `musl-gcc`,
as shown in [the workflow](.github/workflows/build.yml).

GitHub Actions runs formatting, Clippy, Rust tests and the public acceptance
suite for all four targets. Linux ELF checks reject any dynamic loader or
shared-library dependency. PRs, main updates and manual runs produce downloadable
artifacts; a `vX.Y.Z` tag matching the package version publishes a new release
only after every platform passes. Existing releases are never overwritten.
Archives include `BUILD.json` with the source commit, target and binary digest.
See [the workflow](.github/workflows/build.yml) and `scripts/` for packaging.
Mac builds use a macOS 12 deployment target; the CI runtime is macOS 15.

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
The default lifetime is 30 days; `--days` allows 1–90 days. Automatic renewal is on
by default. Use `devices renew` for manual renewal with the existing identity;
`--auto-renew false` opts out when creating a registration.

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
stopped and restart. The CLI provides local administration. Rejection logs are described below.

Data messages are bounded to 64 KiB. Idle streams close after 90 seconds and all
streams reconnect after at most one hour. Clients must reconcile command status
after reconnecting rather than blindly replaying uncertain mutations.

Generated leaf certificates last one year; the private CA lasts ten years. IP leaves renew automatically before expiry. To
renew one manually under the same CA, stop the service, run the following command
and restart. Renewal requires `ca-key.pem`; keep an encrypted offline backup. The
public CA fingerprint is unchanged, so its imported trust remains valid.

```sh
cowork-relay --data-dir ./relay-state renew-ip
```

Renewal writes a fresh key and certificate, then atomically selects them. Previous
certificate files remain in the private directory for operator-managed cleanup.
For domain certificates, renew using your certificate provider. The running
service reloads valid replacements within one minute. If the CA is compromised, expired or the server IP changes, provision a
new identity and explicitly distribute and verify its new trust material.
Back up the private state securely; restoring an old device registry can undo
later revocations. Avoid copying a live registry into a second running service.

`GET /health/live` returns process health over verified HTTPS without exposing
device data. TLS certificates and keys can reload; other configuration is read at startup. SIGINT/SIGTERM closes
connections; clients may reconnect once the service returns.

Container and systemd templates are in [deploy](deploy/). Review paths and network
settings before use. No public deployment is performed by these examples.

## Expiry and automatic renewal

New computer and phone registrations renew automatically by default. The
server extends a registration before expiry, including after a service restart,
without changing its ID, secret, group or target computer. Existing enabled,
unexpired registrations adopt this default once; expired or disabled legacy
registrations do not. Revocation and disabling always take precedence. A
registration file contains an expiry snapshot; updated clients authenticate
against the relay's current state instead of treating that old date as final.

```sh
cowork-relay --data-dir ./relay-state devices renew DEVICE_ID --days 30
cowork-relay --data-dir ./relay-state devices auto-renew DEVICE_ID --enabled false
cowork-relay --data-dir ./relay-state devices auto-renew DEVICE_ID --enabled true
```

`renew` ensures at least the selected number of days from now (1–90), retaining
the existing secret and binding. It never enables a disabled device. Renew an
expired registration manually before enabling its automatic policy. New
`devices add-host` / `add-client` commands accept `--auto-renew false` for fixed
expiry; `--days` sets the renewal period. `devices inspect` and `devices list`
show `expiresAt`, `autoRenew` and `renewalDays`. Remove access with `disable`;
`kick` only disconnects current streams and does not prevent renewal/reconnect.

Generated IP leaf certificates renew within 30 days of expiry by default and
reload for new connections without interrupting existing tunnels. Their CA and
address remain unchanged, so no new registration import is needed. Set
`autoRenewCertificate` to `false` in the private configuration to opt out.
Domain certificates must be renewed by your certificate provider or ACME client;
the relay reloads valid replacements every minute. `status` shows the loaded
certificate's expiry and renewal setting. Private roots are never automatically
replaced: a root nearing expiry requires an administrator and new trust imports.
Keep the private CA signing key available and restrict the state directory.

Use Cowork desktop 0.16.0, Server 0.0.6 and a renewal-capable mobile app
(iOS TestFlight 0.0.1 build 33 or later) together. Upgrade each component;
updating the relay alone does not add renewal support to older clients.
Back up the stopped private state before upgrading: the new registration format
is not readable by older relay binaries. Restore binary and matching backup
together if rolling back.

## Rejection logs

The service writes JSON rejection events to stderr on a separate worker. Each
event contains a fixed reason, the socket source IP, server time and bilingual
message. It never includes request paths, headers, credentials or business data.
For each reason, at most four samples are queued per 30-second window, followed
by a total count. Delivery is best effort: a full or unavailable log output may
drop samples without delaying connection processing. Configure log retention
and access controls with your service manager; source IPs are operational data.

This release adds no per-IP request quota or bandwidth limit and preserves the
existing capacity settings. Log sampling does not reject or block requests.
With the supplied systemd unit, read the logs using:

```sh
journalctl -u cowork-relay --since today
```
