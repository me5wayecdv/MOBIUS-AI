# D-013 — JADX class, method and source lookup API

## Routes

All routes are scoped to an owned investigation and its authorized APK digest.

- `POST /api/v1/scans/{scan_id}/code/decompile` — explicit decompilation/cache warm request.
- `GET /api/v1/scans/{scan_id}/code/classes?prefix=com.example&limit=200` — list classes represented in the verified cache.
- `GET /api/v1/scans/{scan_id}/code/methods?class_name=com.example.Entry&limit=200` — list parsed method declarations for one class.
- `GET /api/v1/scans/{scan_id}/code/source?path=com/example/Entry.java&start_line=1&end_line=40` — retrieve a bounded source excerpt.

## Cache and provenance

Lookup reads only the per-APK SHA-256 / JADX-version cache created by D-012. The adapter revalidates
the manifest identity and the SHA-256/size of every referenced file before returning source. Source
responses include APK SHA-256, JADX version, relative source path, line range and fidelity
(`decompiled` or `smali`). A caller cannot supply an arbitrary filesystem path.

Class names are derived from JADX relative output paths. Java method declarations are parsed
deterministically from the decompiled text; smali method declarations are parsed from `.method`
directives. This is a lookup index, not a full Java parser: complex/multiline declarations and
compiler-generated constructs may not be represented. The original source is not reconstructed.

## Failure behavior

- Missing cache: 404 `JADX_SOURCE_UNAVAILABLE`.
- Missing verified isolated backend on a cache miss: 503 `JADX_BACKEND_UNAVAILABLE`.
- Invalid/corrupt cache: 409 `JADX_CACHE_INVALID`.
- Missing class/source or invalid range: explicit 404/422 response.
- Ownership failures remain indistinguishable from missing investigations (404).

The API process constructs a `ToolRunner` with no execution backend. Therefore a cache hit is
readable, but a cache miss cannot start JADX until a verified, digest-pinned OCI backend is
registered. This is deliberate fail-closed behavior, not a claim that production decompilation
is operational. Current tests seed a manifest-verified cache from a synthetic source fixture and
exercise the real HTTP routes. The JADX execution smoke remains the checked-in DEX fixture only.

No database migration, new dependency, network execution, emulator, or real APK execution is
introduced by this API slice.
