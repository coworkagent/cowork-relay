Linux downloads now use static musl builds for x64 and ARM64. They no longer
require a recent system glibc or an installed musl runtime. This fixes startup
failures reporting missing GLIBC_2.33 or GLIBC_2.34 symbols on older servers.

GitHub Actions builds and runs the Rust and relay acceptance tests on native
Linux and macOS runners for both architectures. Linux packages also pass
startup and local administration checks in Ubuntu 20.04 and Alpine userlands.
Every archive includes its source revision and binary checksum in BUILD.json;
SHA256SUMS covers all four downloads.

macOS binaries require macOS 12 or later and are not Developer ID notarized.
Native Windows administration is not supported. Existing relay configuration,
certificates and device registrations remain compatible: stop the service,
back up private state and replace only the executable. Do not reinitialize it.
