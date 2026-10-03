## Optional iOS task notifications

- Add an optional Apple Push Notification service provider for compatible Cowork computers and iOS clients.
- Deliver generic completion, failure and attention alerts without conversation text or files.
- Authenticate computer requests, restrict delivery to Apple endpoints and apply bounded notification delivery limits.

Notifications require a separately configured APNs signing key, matching app entitlement and user opt-in. Delivery is best effort; this release does not establish physical-device delivery qualification. Existing encrypted relay connections and registration renewal continue without APNs configuration.

Use Cowork 0.18.0, Server 0.0.8 and a notification-capable iOS build together. Back up private state before upgrading. Do not reinitialize an existing state directory. Rollback requires the previous binary and a compatible state backup; restoring old state can undo later revocations.

Linux x64 and ARM64 downloads retain static musl linkage. macOS utilities require macOS 12 or later and are not Developer ID notarized. Native Windows administration is not supported. Each archive includes its source revision and binary checksum; SHA256SUMS covers all four downloads.
