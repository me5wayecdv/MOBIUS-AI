# Artifact storage integrity

Artifact object keys are restricted to the canonical form
`apk/<first-two-sha256-hex>/<full-sha256>.apk`. Absolute paths, traversal-shaped keys,
non-canonical paths, and symlink objects are rejected.

Writes verify that any supplied digest matches the bytes and use a temporary file plus
atomic replacement. Existing objects are checked before reuse. Reads recompute SHA-256 and
fail closed if the stored bytes no longer match the digest encoded in the object key.

These controls protect path confinement and content integrity at the application layer.
The artifact root must still be on a dedicated filesystem/volume with restrictive
permissions, backups, quotas, and operational monitoring.
