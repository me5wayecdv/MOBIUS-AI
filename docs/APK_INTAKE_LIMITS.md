# APK ZIP intake limits

MOBIUS accepts APKs as ZIP containers. The upload path performs metadata-only checks before
storing the original bytes; it does not extract entries or invoke Android parsers.

The intake validator rejects:
- More than 20,000 ZIP entries.
- More than 1 GiB total uncompressed content.
- Any individual entry larger than 256 MiB.
- Compression ratios above 200:1 for entries larger than 1 MiB.
- An AndroidManifest.xml larger than 10 MiB.
- Duplicate entry names, encrypted entries, negative size metadata, and absolute,
  backslash-containing, or parent-traversal entry paths.
- Archives without AndroidManifest.xml.

These checks reduce ZIP ambiguity and obvious decompression/resource-exhaustion cases. They
are not a substitute for ingress request-body limits, isolated APK parsing, CPU/memory/time
quotas, or a constrained worker. The API still receives and buffers the upload before the
service-level byte limit is applied; production remains NO-GO until ingress limits and
out-of-process parsing are implemented.
