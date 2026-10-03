# Cowork Relay transport v1

The relay forwards opaque end-to-end business TLS. Its device credentials are
separate from Remote API credentials. Enrollment and administrative operations
are local-only. Public connections require TLS 1.3 and never follow redirects.

Each registered device has a server-assigned UUID, role `host` or `client`, group,
expiry and a random 256-bit secret. Client registrations bind exactly one host in
the same group. A handset may hold separate registrations for several computers.
Authentication is `Bearer <deviceId>.<base64url-secret>` for host WebSockets and
`Proxy-Authorization: Basic base64(<deviceId>:<base64url-secret>)` for client
CONNECT. Secret comparisons must be constant-time; durable storage holds hashes.
Credentials do not appear in URLs, endpoint certificates or logs.

## Routes

- `GET /relay/v1/control`: authenticated host WebSocket. One active control
  connection per host; replacing it cancels the previous epoch and all its data.
- `GET /relay/v1/data/<connectionId>`: authenticated host WebSocket. Requires
  `X-Cowork-Ticket` matching a live, one-use ticket for the current host epoch.
- `CONNECT <hostRelayDeviceId>.cowork.invalid:443`: client only, exact authority
  and matching Host header (the default `:443` may be omitted in Host). The hostname is a logical route, never resolved or
  used as an arbitrary network destination. Proxy authentication is required.
- `GET /health/live`: minimal process health, no device information.

All public requests reject Cookie, Origin and Referer, duplicate authentication
or Host headers, request bodies and unexpected paths/queries. WebSocket requests
require the configured relay authority. CONNECT requires the exact bound host
authority after normalizing an omitted default port. Only HTTP/1.1 is supported.
No wildcard destination or direct fallback. A syntactically valid CONNECT without
proxy credentials receives 407 with `Proxy-Authenticate: Basic realm="Cowork Relay"`.
This challenge discloses no registered device state. Credentials are sent only
after successful outer TLS verification; invalid credentials are denied with 403.
WebSocket upgrades require subprotocol `cowork.relay.v1` and reject extensions.

## Control and data

Control text messages use `control.schema.json`. The server sends `ready` with an
epoch UUID, then `open` with a connection UUID, ticket and short expiry. The host
opens one data WebSocket per requested stream. Tickets bind the host, client,
epoch and connection; consumption rechecks both devices and is atomic. A client
receives CONNECT 200 only after the host attaches. Unknown/offline/busy targets
yield a bounded error without disclosing another device's registration.

The data WebSocket carries binary fragments of the end-to-end TLS byte stream,
without compression or interpretation. WebSocket message boundaries are not TLS
record boundaries. Each connection has bounded frames, buffers and timeouts.
Frames and assembled messages are at most 64 KiB (4 KiB for control).
Tickets expire after ten seconds. Control connections ping every 30 seconds and
require an answering pong within 90 seconds. Data streams close after 90 seconds
without byte transfer, a blocked write of 30 seconds, or a one-hour lifetime.
Ping/pong is transport-only. Closing either side cancels both directions.

Disabling a device commits durable state before acknowledging the operation;
new authentication, ticket issuance and redemption check that state. Existing
streams close and pending tickets are cancelled. Kicking only cancels current
connections; reauthentication remains allowed. Disabling a host closes its
clients' streams. Neither action revokes business grants on the computer or
cancels an already accepted Agent task.

This initial transport uses independently revocable high-entropy bearer
credentials protected by authenticated TLS, rather than the earlier proposed
challenge-signing enrollment. Business TLS authenticates the paired computer
independently. Device-key proof of possession can be a separate future protocol;
implementations must not claim it is present in v1.

## Private gateway integration

`config.schema.json` defines the exact registration file emitted by the relay
CLI, its public trust descriptor and the private gateway relay bootstrap. The
bootstrap requires a host registration and separate business TLS certificate
and key. The inner TLS origin is derived from that relay host ID; configuration
must not introduce an arbitrary forwarding destination.

Bridge v1 optionally carries `relay` in its initial private bootstrap. A gateway
must validate all relay TLS/trust inputs before opening network work and must
stop every outbound relay task when the parent pipe closes. Public root stores
and a single explicitly imported private CA are separate trust modes; neither
allows disabled verification or redirects. The registration secret never enters
public business headers or status notifications.

Every request received over this path includes `ingress: "relay"` in its private
Bridge request, including pairing, RPC, event polling and file chunks. The
gateway sets the marker from the accepted transport, never from client headers,
body fields or route strings. The Host must reject relay traffic without the
global and device-specific internet permission. A missing marker retains the
existing LAN path and does not upgrade old device permissions.

The gateway may send a `relay.status` Bridge frame after ordinary readiness to
report connecting, online, offline, access-denied, certificate-untrusted or
protocol-incompatible. These bounded states contain no keys or raw network
errors. Online describes an authenticated relay control channel, not proof that
any particular phone or business command is authorized.

## Signed computer endpoints and pairing

`endpoint.schema.json` and `endpoint.js` define a separate public descriptor and
`cowork.pairing/1-relay` invitation. The administrator supplies each phone's
client registration privately; the phone imports its outer trust explicitly.
The invitation contains only the Host CA, signed endpoint, short pairing secret
and expiry. It contains no relay client secret and cannot provision a relay
registration. Its origin and relay host UUID must exactly match that imported
client registration. The six-digit comparison and local approval remain required.

Endpoint signatures are ECDSA P-256 SHA-256 using the retained paired Host CA key,
with X9.62 DER signature bytes in standard Base64. The UTF-8 signing payload is
these ASCII fields in this exact order, separated by LF, including a final LF:
`protocol`, `hostId`, `relayOrigin`, `relayHostId`, `httpsOrigin`,
`certificateSha256`, `issuedAt`, `expiresAt`. Times are canonical decimal integer
Unix seconds. The protocol is `cowork.relay.endpoint/1`, distinct from LAN
endpoint signing. Lifetime is at most 120 seconds with 30 seconds of future
clock tolerance. Unknown fields, alternate authorities, default inner ports,
fragments and normalized-but-different origins are rejected. `httpsOrigin` is
exactly `https://<relayHostId>.cowork.invalid`.

A supporting Host sets `relay.endpointDiscovery: true` in private bootstrap.
Only that explicitly enabled relay transport exposes
`GET /remote/v1/relay/endpoint`; the LAN listener and older bootstrap do not.
The request has no body, business authorization, cookies, query or redirects.
It issues the private `relay.endpoint` operation with required `ingress: relay`
and empty payload. The Host checks global relay enablement and signs its current
live certificate; it returns no pairing secret, device list, grant or root CA.
The gateway validates the response shape, exact inner origin and bounded size.
It does not cache proofs. This operation cannot run business methods.

To recover a changed leaf, a registered phone first authenticates outer TLS and
CONNECT, then performs only this bounded read under the saved Host CA with
platform inner TLS name, chain and expiry validation. This recovery-only read
carries no business credential and cannot execute arbitrary requests. Verify the
fresh descriptor signature with that same saved CA, match saved Cowork Host ID
and the imported relay origin/host UUID, then perform new native TLS using the
advertised leaf pin and authenticated `connection.hello`. Persist the endpoint
only after hello proves the same Host identity. No step replaces a paired CA;
a different Host/root or relay registration requires explicit local action.
Rejecting or timing out a proof preserves the previous saved endpoint.

## Registration renewal

Registrations may carry `autoRenew` and `renewalDays` (1–90). New relay
registrations default to automatic renewal. The relay persists renewal before
publishing it; identity, credential hash, group and target remain unchanged.
Disabled devices never renew. Existing active registrations migrate to the
default; expired legacy registrations require an administrator to renew them.
An explicit persisted automatic policy continues across service downtime.

`GET /relay/v1/registration` is a bodyless, non-redirecting HTTPS read, authenticated
with `Authorization: Bearer <deviceId>.<secret>` under the imported relay trust.
It returns `registrationStatus`: only this device and its bound host metadata,
plus server time. Expired/disabled credentials can read their own status but
cannot establish a tunnel. It returns no credentials or trust material.
Business CONNECT/control authentication always checks current relay state;
imported expiry timestamps are snapshots, not a substitute for this check.
Clients must retain scoped certificate and hostname checks on every request.

Remote v1 `access.lease.v1` is explicitly negotiated. A supporting hello contains
`access` with the desktop-authoritative expiry and renewal policy. Renewal never
changes grants or resurrects revoked devices. Invitation expiry remains separate
from device access expiry. Old peers receive no new hello result fields.

## Optional notification provider

A relay administrator may configure an APNs signing key, topic and environment.
The key remains on the relay. Authenticated, active Host registrations may read
`/relay/v1/push/status` and POST `/relay/v1/push/send`. Client registrations may
not call either endpoint. The exact request and result definitions are in
`config.schema.json`. No caller-defined text, topic, target URL, command or
approval is accepted. The provider constructs bilingual generic alerts and
includes only opaque Host, session and event identifiers for navigation.

The Host stores native device tokens in its OS-sealed notification registry,
checks the current device grant before each send, and expires opt-ins after
seven days without renewal. Notification registration uses the optional
`notifications.push.v1` capability, revision comparison and explicit disable.
Changing grants invalidates the registration; enabling it again requires a
fresh authorized request. A notification is never authority to read or act.
Opening it must use the saved paired identity, reconnect and synchronize under
current grants. Pending actions always require the normal interactive flow.

Provider requests have a 4 KiB limit, a maximum five-minute lifetime, bounded
rate and concurrency limits, and event deduplication. Acceptance means APNs
accepted the request; it does not prove delivery or that the user read it.
No automatic retry is made after an uncertain delivery. Relay tunneling keeps
business TLS opaque; this opt-in channel does not carry task text or files.
