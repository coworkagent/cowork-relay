Computer and phone registrations now renew automatically by default while
retaining their credentials and target bindings. Administrators can renew a
registration manually or opt into fixed expiry. Disabled registrations stay
disabled, including after restart.

Generated IP certificates renew under the existing private CA without another
trust import. Valid replacement certificates reload for new connections while
existing tunnels continue. Domain certificates still need an external renewal
provider. Private root certificates are never silently replaced.

Rejection logs provide fixed reasons, source IPs and aggregate counts without
recording credentials or business content. Logging uses a bounded queue and
never participates in admission decisions. Existing connection capacities are
unchanged; no per-IP request or bandwidth limit is added.

Use Cowork 0.16.0, Server 0.0.6 and renewal-capable mobile clients together. Stop
the service and back up private state before upgrading. The new registration
format cannot be read by older relay binaries; rollback requires both the old
binary and its matching state backup. Restoring an old registry can undo later
revocations. Do not reinitialize an existing state directory.

Linux x64 and ARM64 downloads retain static musl linkage. macOS utilities
require macOS 12 or later and are not Developer ID notarized. Native Windows
administration is not supported. Each archive includes its source revision
and binary checksum; SHA256SUMS covers all four downloads.
