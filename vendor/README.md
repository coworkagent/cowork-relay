# Pinned relay contract

The package archive is produced by cowork-protocol 0.0.8 (stable source, commit
`243b6a2da629b3e3d1286450799d3c7212f7ef27`). Its relay
schema and specification are copied without edits. `digests.json` pins the
archive and all three extracted files; the Rust build rejects digest changes.
Acceptance checks also compare the extracted bytes with the npm package.
Create a new versioned archive when the upstream contract changes. Do not
modify an extracted schema or overwrite this archive independently.
