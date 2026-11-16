"""RECON: turn an uploaded APK into an evidence-backed attack surface.

Deterministic. No model is called here, and that is a design choice rather than a
limitation: the manifest is a structured document, and asking a language model to read one
would add variance to the most reliable step in the pipeline.

What RECON may and may not conclude is the point of the module:

* It *establishes* facts - this activity is exported, this service is guarded by that
  permission - and every fact carries the SHA-256 of the manifest bytes it came from.
* It *does not* confirm findings. Reachability of a privileged sink needs code analysis
  (SPECTRE), so RECON contributes only the attributes it can see. A candidate that enters
  validation from here therefore lands in INSUFFICIENT_EVIDENCE, never CONFIRMED.
* It records the components it *excludes* as well as those it queues, so a reviewer can see
  that the launcher was considered and dismissed rather than never looked at.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from ..adapters.android_manifest import (
    ManifestParseError,
    extract_manifest_bytes,
    is_binary_axml,
    parse_surface,
    to_text_xml,
)
from ..adapters.events import SqlEventStore, utcnow
from ..adapters.models import ApplicationRow, AuthorizationRow, FrontierEntryRow, InvestigationRow, ObservationRow
from ..core import fsm
from ..core.enums import EvidenceKind, Fidelity, InvestigationState, ObservationKind
from ..core.ids import IdPrefix, new_id
from ..core.manifest import Component, ExportSource, ManifestSurface, candidates, describe
from .artifacts import ArtifactStore
from .errors import AuthorizationRequired, ManifestInvalid, NotFound, ScanStateConflict
from .evidence import EvidenceService

AGENT = "RECON"
_MANIFEST_EVIDENCE_KINDS = (EvidenceKind.MANIFEST,)


class ReconService:
    def __init__(self, session: Session, store: ArtifactStore) -> None:
        self._session = session
        self._store = store
        self._evidence = EvidenceService(session, store)

    def run(self, investigation_id: str, *, manifest_xml: bytes | None = None) -> dict[str, object]:
        row = self._session.get(InvestigationRow, investigation_id)
        if row is None:
            raise NotFound(f"investigation {investigation_id} not found")
        state = InvestigationState(row.state)
        if state is not InvestigationState.RECON:
            raise ScanStateConflict(
                f"RECON may only run from RECON; investigation is in {state.value}"
            )

        application = self._session.get(ApplicationRow, row.application_id)
        if application is None:  # pragma: no cover - FK makes this unreachable
            raise NotFound(f"application {row.application_id} not found")

        surface, manifest_xml = self._load_surface(application, manifest_xml_override=manifest_xml)

        # The authorization form's package name is an assertion, not proof. Bind it to
        # the package parsed from the exact APK bytes before recording a usable surface.
        authorization = (
            self._session.get(AuthorizationRow, row.authorization_id)
            if row.authorization_id else None
        )
        if authorization is None:
            raise AuthorizationRequired("investigation has no active APK authorization")
        if authorization.target_package != surface.package_name:
            raise AuthorizationRequired(
                "authorized target package does not match the package parsed from this APK"
            )

        evidence = self._record_manifest(investigation_id, manifest_xml, surface)

        self._update_application(application, surface)
        self._record_observations(investigation_id, surface, evidence.id)
        delta = describe(surface)
        queued = self._queue_candidates(investigation_id, surface)

        store = SqlEventStore(self._session)
        store.emit(
            investigation_id,
            "surface_ready",
            {
                "package": surface.package_name,
                "evidence_id": evidence.id,
                "components": delta.components,
                "exported": delta.exported,
                "unguarded_exported": delta.unguarded,
                "candidates": delta.candidates,
                "excluded_launchers": delta.excluded_launchers,
                "frontier_enqueued": queued,
                "notes": list(delta.notes),
            },
            actor=AGENT,
        )
        result = fsm.transition(
            state, InvestigationState.SURFACE_READY, authorization_id=row.authorization_id
        )
        row.state = result.current.value
        # Same transaction as the state write, same pattern as IntakeService.advance: the
        # event log and the state can never disagree about what happened.
        store.emit(investigation_id, result.event_type, result.event_payload, actor="NEXUS")
        self._session.flush()

        return {
            "package_name": surface.package_name,
            "version_name": surface.version_name,
            "version_code": surface.version_code,
            "min_sdk": surface.min_sdk,
            "target_sdk": surface.target_sdk,
            "permissions": list(surface.permissions),
            "components": delta.components,
            "exported": delta.exported,
            "unguarded_exported": delta.unguarded,
            "candidates": delta.candidates,
            "excluded_launchers": delta.excluded_launchers,
            "frontier_enqueued": queued,
            "notes": list(delta.notes),
            "evidence_id": evidence.id,
            "state": row.state,
        }

    def surface(self, investigation_id: str) -> dict[str, object]:
        """Read back the surface recorded by the last RECON run."""
        row = self._session.get(InvestigationRow, investigation_id)
        if row is None:
            raise NotFound(f"investigation {investigation_id} not found")
        app = self._session.get(ApplicationRow, row.application_id)
        observations = (
            self._session.query(ObservationRow)
            .filter(
                ObservationRow.investigation_id == investigation_id,
                ObservationRow.subject_type.in_(("component", "application")),
                ObservationRow.agent == AGENT,
            )
            .order_by(ObservationRow.created_at.asc())
            .all()
        )
        queued = (
            self._session.query(FrontierEntryRow)
            .filter(
                FrontierEntryRow.investigation_id == investigation_id,
                FrontierEntryRow.state == "queued",
            )
            .all()
        )
        return {
            "package_name": app.package_name if app else None,
            "version_name": app.version_name if app else None,
            "observations": [
                {
                    "id": o.id,
                    "subject_type": o.subject_type,
                    "subject_ref": o.subject_ref,
                    "statement": o.statement,
                    "attributes": o.attributes,
                    "evidence_refs": o.evidence_refs,
                    "kind": o.kind,
                    "fidelity": o.fidelity,
                }
                for o in observations
            ],
            "frontier": [
                {
                    "id": f.id,
                    "action": f.action,
                    "action_args": f.action_args,
                    "required_agent": f.required_agent,
                    "relates_to_maswe": f.relates_to_maswe,
                }
                for f in queued
            ],
        }

    # -- internals -----------------------------------------------------------------

    def _load_surface(
        self, application: ApplicationRow, *, manifest_xml_override: bytes | None = None
    ) -> tuple[ManifestSurface, bytes]:
        try:
            if manifest_xml_override is None:
                apk = self._store.get(application.artifact_key)
                raw = extract_manifest_bytes(apk)
                binary = is_binary_axml(raw)
                manifest_xml = to_text_xml(raw)
            else:
                manifest_xml = manifest_xml_override
                binary = True
            surface = parse_surface(manifest_xml, decoded_from_binary=binary)
        except ManifestParseError as exc:
            raise ManifestInvalid(str(exc)) from exc
        return surface, manifest_xml

    def _record_manifest(self, investigation_id: str, manifest_xml: bytes, surface: ManifestSurface):
        return self._evidence.record(
            investigation_id=investigation_id,
            kind=_MANIFEST_EVIDENCE_KINDS[0],
            content=manifest_xml,
            summary=(
                f"Decoded AndroidManifest.xml for {surface.package_name} "
                f"({len(surface.components)} components, {len(surface.permissions)} permissions)"
            ),
            produced_by=AGENT,
        )

    def _update_application(self, application: ApplicationRow, surface: ManifestSurface) -> None:
        application.package_name = surface.package_name
        application.version_name = surface.version_name
        application.version_code = surface.version_code
        application.min_sdk = surface.min_sdk
        application.target_sdk = surface.target_sdk
        self._session.flush()

    def _record_observations(
        self, investigation_id: str, surface: ManifestSurface, evidence_id: str
    ) -> None:
        fidelity = (
            Fidelity.BINARY_XML if surface.decoded_from_binary else Fidelity.DECOMPILED
        )
        self._add_observation(
            investigation_id=investigation_id,
            subject_type="application",
            subject_ref=surface.package_name,
            statement=(
                f"{surface.package_name} declares {len(surface.components)} components, "
                f"{len(surface.exported())} exported and {len(surface.unguarded_exported())} "
                "exported without a permission guard"
            ),
            attributes=dict(surface.summary()),
            evidence_id=evidence_id,
            fidelity=fidelity,
        )
        for component in surface.components:
            self._add_observation(
                investigation_id=investigation_id,
                subject_type="component",
                subject_ref=component.name,
                statement=self._statement(component),
                attributes={
                    "kind": component.kind,
                    "exported": component.exported,
                    "export_source": component.export_source.value,
                    "permission": component.permission,
                    "enabled": component.enabled,
                    "launcher": component.is_launcher,
                    "deep_link": component.has_deep_link,
                    "is_candidate": component in candidates(surface),
                },
                evidence_id=evidence_id,
                fidelity=fidelity,
            )

    @staticmethod
    def _statement(component: Component) -> str:
        reach = "exported" if component.exported else "not exported"
        if component.export_source is not ExportSource.DECLARED:
            reach += f" ({component.export_source.value})"
        guard = (
            f"guarded by {component.permission}"
            if component.permission
            else "with no permission guard"
        )
        return f"{component.kind} {component.name} is {reach}, {guard}"

    def _add_observation(
        self,
        *,
        investigation_id: str,
        subject_type: str,
        subject_ref: str,
        statement: str,
        attributes: dict[str, object],
        evidence_id: str,
        fidelity: Fidelity,
    ) -> None:
        self._session.add(
            ObservationRow(
                id=new_id(IdPrefix.OBSERVATION),
                investigation_id=investigation_id,
                agent=AGENT,
                kind=ObservationKind.FACT.value,
                fidelity=fidelity.value,
                subject_type=subject_type,
                subject_ref=subject_ref,
                statement=statement,
                attributes=attributes,
                maswe=[],
                confidence=1.0,  # a fact, and the CHECK constraint agrees
                evidence_refs=[evidence_id],
                created_at=utcnow(),
            )
        )
        self._session.flush()

    def _queue_candidates(self, investigation_id: str, surface: ManifestSurface) -> int:
        queued = 0
        for component in candidates(surface):
            self._session.add(
                FrontierEntryRow(
                    id=new_id(IdPrefix.FRONTIER),
                    investigation_id=investigation_id,
                    action="find_api_refs",
                    action_args={"component": component.name, "source": "manifest"},
                    required_agent="SPECTRE",
                    relates_to_maswe=["MASWE-0029"],
                    score=0.0,  # NEXUS scores it when it ranks the frontier
                    depth=0,
                    state="queued",
                    attempts=0,
                    inserted_at=utcnow(),
                )
            )
            queued += 1
        self._session.flush()
        return queued
