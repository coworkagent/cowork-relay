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
