# Pinned relay contract

The package archive is produced by cowork-protocol 0.0.6. Its relay
schema and specification are copied without edits. `digests.json` pins the
archive and all three extracted files; the Rust build rejects digest changes.
Acceptance checks also compare the extracted bytes with the npm package.
Create a new versioned archive when the upstream contract changes. Do not
modify an extracted schema or overwrite this archive independently.
