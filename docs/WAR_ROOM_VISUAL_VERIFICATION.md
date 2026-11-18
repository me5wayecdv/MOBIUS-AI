# War Room visual verification and D-056 browser E2E

## What the browser test does

`frontend/e2e/war-room.spec.js` drives the actual FastAPI app and browser page. It uploads a deterministic CI-only APK, creates an exact-digest authorization and investigation, stores evidence, seeds a clearly labelled synthetic observation/hypothesis, rebuilds the persisted graph, runs the local positive/negative PoC harness, writes the report, and verifies event sequence IDs are unchanged after refresh.

The seeded fixture is for UI/API/persistence integration only. It is not the final intentionally vulnerable APK and does not claim real APK runtime execution, source indexing, or Ollama-backed adaptive reasoning.

## CI artifact

Workflow job: **War Room browser E2E · screenshots**  
Artifact name: `mobius-war-room-visual-e2e-<run_id>`  
Retention: 14 days

Expected files:

- `d050-mission-coverage-desktop.png`, `d050-mission-coverage-mobile.png`
- `d051-agent-network-desktop.png`, `d051-agent-network-mobile.png`
- `d052-timeline-desktop.png`, `d052-timeline-mobile.png`
- `d053-code-studio-desktop.png`, `d053-code-studio-mobile.png`
- `d054-attack-graph-desktop.png`, `d054-attack-graph-mobile.png`
- `d055-poc-report-desktop.png`, `d055-poc-report-mobile.png`
- `d033-react-flow-desktop.png`, `d033-react-flow-mobile.png`
- `d056-01-upload-and-investigation.png` through `d056-06-refresh-replay.png`

The screenshot artifact is evidence for owner review, not an automatic visual pass. D-033 and D-050–D-055 remain visually unaccepted until the project owner inspects both viewport sizes.

## Honest panel behavior

- D-050 reads APK identity, digest, authorization package scope, investigation state and host-tool availability.
- D-051 renders only agents/tools present in persisted lifecycle events. An empty panel is an explicit absence of event data.
- D-052 replays persisted events and refreshes from the event API cursor. D-056 compares every sequence ID before and after reload.
- D-053 shows persisted observations/evidence references; when source/DEX indexing is absent, it says so rather than fabricating code.
- D-054 renders the persisted graph and hypotheses.
- D-055 renders persisted PoC runs and the stored report.

No deploy or publication is part of this workflow.
