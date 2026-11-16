"""Intake: uploading an APK, granting authorisation, opening an investigation.

This is where the project's legal and ethical controls actually live. Everything else in
MOBIUS is analysis; this module decides whether analysis is allowed to happen at all.

Note on flushing. SQLAlchemy derives insert order from ``relationship()`` declarations,
not from foreign keys. With no relationships configured, a flush can emit a child row
before its parent and fail the FK - which is exactly what happened when this module was
first written. Rather than add relationships (and their cascade semantics) the service
flushes explicitly in dependency order: user -> application/authorisation ->
investigation -> event. Deterministic, and visible at the call site.
"""

from __future__ import annotations

import zipfile
from datetime import datetime, timezone
from io import BytesIO

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..adapters.events import utcnow
from ..adapters.models import (
    ApplicationRow,
    AuthorizationRow,
    InvestigationRow,
    UserRow,
)
from ..core import fsm
from ..core.enums import Intensity, InvestigationState
from ..core.ids import IdPrefix, new_id
from ..core.schemas import (
    Application,
    Authorization,
    Budget,
    BudgetUsage,
    Investigation,
    LLMSharing,
)
from .artifacts import ArtifactStore
from .errors import (
    ApkInvalid,
    ApkTooLarge,
    AuthorizationExpired,
    AuthorizationRequired,
    AuthorizationRevoked,
    IntensityDisabledByPolicy,
    IntensityNotGranted,
    NotFound,
    ScanStateConflict,
)

MAX_APK_BYTES = 200 * 1024 * 1024
MAX_APK_ENTRIES = 20_000
MAX_APK_UNCOMPRESSED_BYTES = 1024 * 1024 * 1024
MAX_APK_ENTRY_BYTES = 256 * 1024 * 1024
MAX_APK_COMPRESSION_RATIO = 200
MAX_MANIFEST_BYTES = 10 * 1024 * 1024
_REQUIRED_ENTRY = "AndroidManifest.xml"


def _validate_zip_container(zf: zipfile.ZipFile) -> None:
    """Reject ambiguous or resource-exhausting ZIP metadata without extracting entries."""
    infos = zf.infolist()
    if len(infos) > MAX_APK_ENTRIES:
        raise ApkInvalid(f"APK contains too many ZIP entries (maximum {MAX_APK_ENTRIES})")

    seen: set[str] = set()
    total_uncompressed = 0
    manifest_found = False
    for info in infos:
        name = info.filename
        if name in seen:
            raise ApkInvalid(f"APK contains duplicate ZIP entry: {name!r}")
        seen.add(name)
        if name.startswith("/") or "\\" in name or ".." in name.split("/"):
            raise ApkInvalid(f"APK contains an unsafe ZIP entry path: {name!r}")
        if info.flag_bits & 0x1:
            raise ApkInvalid(f"APK contains an encrypted ZIP entry: {name!r}")
        if info.file_size < 0 or info.compress_size < 0:
            raise ApkInvalid(f"APK contains invalid ZIP size metadata: {name!r}")
        if info.file_size > MAX_APK_ENTRY_BYTES:
            raise ApkInvalid(f"APK ZIP entry exceeds the per-entry limit: {name!r}")
        total_uncompressed += info.file_size
        if total_uncompressed > MAX_APK_UNCOMPRESSED_BYTES:
            raise ApkInvalid("APK exceeds the total uncompressed ZIP size limit")
        if info.file_size > 1024 * 1024:
            ratio = info.file_size / max(1, info.compress_size)
            if ratio > MAX_APK_COMPRESSION_RATIO:
                raise ApkInvalid(f"APK ZIP entry has an excessive compression ratio: {name!r}")
        if name == _REQUIRED_ENTRY:
            manifest_found = True
            if info.file_size > MAX_MANIFEST_BYTES:
                raise ApkInvalid("AndroidManifest.xml exceeds the manifest size limit")

    if not manifest_found:
        raise ApkInvalid(f"missing {_REQUIRED_ENTRY}; this is not an APK")


def parse_ts(value: str) -> datetime:
    """Parse the ISO-8601 timestamps written by ``utcnow``."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def is_expired(expires_at: str, *, now: datetime | None = None) -> bool:
    reference = now or datetime.now(timezone.utc)
    return parse_ts(expires_at) <= reference


class IntakeService:
    def __init__(self, session: Session, store: ArtifactStore) -> None:
        self._session = session
        self._store = store

    # -- users ---------------------------------------------------------------------
    def _ensure_user(self, user_id: str) -> None:
        """Create a placeholder user row on first sight.

        STUB: real authentication (JWT, argon2id password hashes) is Phase 2 task T-049
        and is not implemented. This exists so foreign keys resolve in development. The
        API refuses to start with this path active when MOBIUS_ENV=production - see
        mobius.api.deps.
        """
        if self._session.get(UserRow, user_id) is not None:
            return
        self._session.add(
            UserRow(
                id=user_id,
                email=f"{user_id}@local.invalid",
                display_name=user_id,
                role="analyst",
                password_hash="!stub-not-a-credential",
                created_at=utcnow(),
            )
        )
        self._session.flush()

    # -- applications --------------------------------------------------------------
    def create_application(
        self, data: bytes, filename: str, *, uploaded_by: str
    ) -> tuple[Application, bool]:
        """Validate and store an APK. Returns ``(application, created)``.

        Validation here is deliberately shallow - is it a ZIP, does it contain a manifest -
        because deep parsing is RECON's job and doing it during upload would make a failed
        parse look like a failed upload. The one thing it must get right is that the
        artefact is what it claims to be before anything an authorisation can bind to.
        """
        if len(data) == 0:
            raise ApkInvalid("empty upload")
        if len(data) > MAX_APK_BYTES:
            raise ApkTooLarge(f"APK exceeds {MAX_APK_BYTES} bytes")
        if not zipfile.is_zipfile(BytesIO(data)):
            raise ApkInvalid("not a ZIP archive; an APK must be a ZIP")
        try:
            with zipfile.ZipFile(BytesIO(data)) as zf:
                _validate_zip_container(zf)
        except zipfile.BadZipFile as exc:
            raise ApkInvalid(f"corrupt ZIP: {exc}") from exc

        sha256 = ArtifactStore.digest(data)
        existing = self._session.execute(
            select(ApplicationRow).where(ApplicationRow.sha256 == sha256)
        ).scalar_one_or_none()
        if existing is not None:
            return self._to_application(existing), False

        self._ensure_user(uploaded_by)
        key, size = self._store.put(data, sha256)
        row = ApplicationRow(
            id=new_id(IdPrefix.APPLICATION),
            sha256=sha256,
            file_size=size,
            artifact_key=key,
            uploaded_by=uploaded_by,
            created_at=utcnow(),
        )
        self._session.add(row)
        self._session.flush()
        return self._to_application(row), True

    def get_application(self, application_id: str) -> Application:
        row = self._session.get(ApplicationRow, application_id)
        if row is None:
            raise NotFound(f"application {application_id} not found")
        return self._to_application(row)

    def find_application_by_hash(self, sha256: str) -> Application | None:
        row = self._session.execute(
            select(ApplicationRow).where(ApplicationRow.sha256 == sha256)
        ).scalar_one_or_none()
        return None if row is None else self._to_application(row)

    # -- authorisations ------------------------------------------------------------
    def create_authorization(
        self,
        *,
        apk_sha256: str,
        target_package: str,
        scope_text: str,
        statement: str,
        max_intensity: int,
        granted_by: str,
        expires_at: str,
    ) -> Authorization:
        if max_intensity not in Intensity.ALL:
            raise IntensityNotGranted(f"max_intensity must be 0-3, got {max_intensity}")
        self._ensure_user(granted_by)
        domain = Authorization(
            apk_sha256=apk_sha256,
            target_package=target_package,
            scope_text=scope_text,
            statement=statement,
            max_intensity=max_intensity,
            granted_by=granted_by,
            expires_at=expires_at,
        )
        row = AuthorizationRow(
            id=domain.id,
            granted_by=granted_by,
            target_package=target_package,
            apk_sha256=apk_sha256,
            scope_text=scope_text,
            max_intensity=max_intensity,
            statement=statement,
            expires_at=expires_at,
            created_at=utcnow(),
        )
        self._session.add(row)
        self._session.flush()
        return domain

    def get_authorization(self, authorization_id: str) -> AuthorizationRow:
        row = self._session.get(AuthorizationRow, authorization_id)
        if row is None:
            raise AuthorizationRequired(f"authorization {authorization_id} not found")
        return row

    # -- investigations ------------------------------------------------------------
    def create_investigation(
        self,
        *,
        application_id: str,
        authorization_id: str,
        objective: str,
        intensity: int,
        created_by: str,
        budget: Budget | None = None,
    ) -> Investigation:
        app_row = self._session.get(ApplicationRow, application_id)
        if app_row is None:
            raise NotFound(f"application {application_id} not found")

        auth = self.get_authorization(authorization_id)

        # FR-AUTH-3: authorisation is pinned to the artefact, not the package name. A
        # new build of the same app is a different target and needs its own grant.
        if auth.apk_sha256 != app_row.sha256:
            raise AuthorizationRequired(
                "authorization is bound to a different APK hash; "
                "upload the authorised artefact or obtain a new authorisation"
            )
        if auth.revoked_at is not None:
            raise AuthorizationRevoked(f"authorization {authorization_id} was revoked")
        if is_expired(auth.expires_at):
            raise AuthorizationExpired(f"authorization {authorization_id} expired")
        if intensity > auth.max_intensity:
            raise IntensityNotGranted(
                f"requested intensity {intensity} exceeds granted {auth.max_intensity}"
            )
        if intensity > Intensity.MAX_ENABLED:
            raise IntensityDisabledByPolicy(
                f"intensity {intensity} is disabled in v1; maximum enabled is {Intensity.MAX_ENABLED}"
            )

        self._ensure_user(created_by)
        domain = Investigation(
            application_id=application_id,
            authorization_id=authorization_id,
            created_by=created_by,
            objective=objective,
            intensity=intensity,
            state=InvestigationState.INTAKE,
            budget=budget or Budget(),
            used=BudgetUsage(),
            llm_data_sharing=LLMSharing(enabled=False),
        )
        row = InvestigationRow(
            id=domain.id,
            application_id=application_id,
            authorization_id=authorization_id,
            created_by=created_by,
            objective=objective,
            intensity=intensity,
            state=InvestigationState.INTAKE.value,
            budget_json=domain.budget.model_dump(),
            used_json=domain.used.model_dump(),
            llm_data_sharing=domain.llm_data_sharing.model_dump(),
            event_seq=0,
            created_at=utcnow(),
        )
        self._session.add(row)
        self._session.flush()
        return self._to_investigation(row)

    def advance(self, investigation_id: str, target: InvestigationState, *, reason: str | None = None):
        """Move an investigation, appending exactly one event with the change.

        The state write and the event append share the caller's transaction, so they commit
        or roll back together (docs/EVENT_ARCHITECTURE.md 2).
        """
        from ..adapters.events import SqlEventStore

        row = self._session.get(InvestigationRow, investigation_id)
        if row is None:
            raise NotFound(f"investigation {investigation_id} not found")

        result = fsm.transition(
            InvestigationState(row.state),
            target,
            reason=reason,
            authorization_id=row.authorization_id,
        )
        row.state = result.current.value
        store = SqlEventStore(self._session)
        store.emit(
            investigation_id,
            result.event_type,
            result.event_payload,
            actor="NEXUS",
        )
        self._session.flush()
        return result

    def start(self, investigation_id: str):
        """INTAKE -> RECON, emitting investigation_started then the transition."""
        from ..adapters.events import SqlEventStore

        row = self._session.get(InvestigationRow, investigation_id)
        if row is None:
            raise NotFound(f"investigation {investigation_id} not found")
        store = SqlEventStore(self._session)
        store.emit(
            investigation_id,
            "investigation_started",
            {
                "objective": row.objective,
                "intensity": row.intensity,
                "budget": row.budget_json,
            },
            actor="NEXUS",
        )
        return self.advance(investigation_id, InvestigationState.RECON, reason="authorised")

    # -- pause / resume / cancel (ADR-017: pause is a flag) --------------------------
    def pause(self, investigation_id: str, *, by: str, reason: str | None = None):
        from ..adapters.events import SqlEventStore

        row = self._session.get(InvestigationRow, investigation_id)
        if row is None:
            raise NotFound(f"investigation {investigation_id} not found")
        if fsm.is_terminal(InvestigationState(row.state)):
            raise ScanStateConflict(f"cannot pause a {row.state} investigation")
        if row.paused_at is not None:
            return self._to_investigation(row)  # idempotent
        self._ensure_user(by)
        row.paused_at = utcnow()
        row.paused_by = by
        row.pause_reason = reason
        SqlEventStore(self._session).emit(
            investigation_id, "investigation_paused", {"by": by, "reason": reason}, actor=by
        )
        self._session.flush()
        return self._to_investigation(row)

    def resume(self, investigation_id: str, *, by: str):
        from ..adapters.events import SqlEventStore

        row = self._session.get(InvestigationRow, investigation_id)
        if row is None:
            raise NotFound(f"investigation {investigation_id} not found")
        if row.paused_at is None:
            return self._to_investigation(row)  # idempotent
        row.paused_at = None
        row.paused_by = None
        row.pause_reason = None
        SqlEventStore(self._session).emit(
            investigation_id, "investigation_resumed", {"by": by}, actor=by
        )
        self._session.flush()
        return self._to_investigation(row)

    def cancel(self, investigation_id: str, *, by: str, reason: str = "cancelled"):
        from ..adapters.events import SqlEventStore

        row = self._session.get(InvestigationRow, investigation_id)
        if row is None:
            raise NotFound(f"investigation {investigation_id} not found")
        state = InvestigationState(row.state)
        if fsm.is_terminal(state):
            return self._to_investigation(row)
        row.state = InvestigationState.CANCELLED.value
        row.stop_reason = "cancelled"
        row.finished_at = utcnow()
        SqlEventStore(self._session).emit(
            investigation_id,
            "scan_cancelled",
            {"by": by, "reason": reason},
            actor=by,
        )
        self._session.flush()
        return self._to_investigation(row)

    # -- reads ----------------------------------------------------------------------
    def get_investigation(self, investigation_id: str) -> Investigation:
        row = self._session.get(InvestigationRow, investigation_id)
        if row is None:
            raise NotFound(f"investigation {investigation_id} not found")
        return self._to_investigation(row)

    # -- row -> domain --------------------------------------------------------------
    @staticmethod
    def _to_application(row: ApplicationRow) -> Application:
        return Application(
            id=row.id,
            sha256=row.sha256,
            package_name=row.package_name,
            version_name=row.version_name,
            version_code=row.version_code,
            min_sdk=row.min_sdk,
            target_sdk=row.target_sdk,
            file_size=row.file_size,
            artifact_key=row.artifact_key,
        )

    @staticmethod
    def _to_investigation(row: InvestigationRow) -> Investigation:
        return Investigation(
            id=row.id,
            application_id=row.application_id,
            authorization_id=row.authorization_id,
            created_by=row.created_by,
            objective=row.objective,
            intensity=row.intensity,
            state=InvestigationState(row.state),
            budget=Budget(**row.budget_json),
            used=BudgetUsage(**row.used_json),
            llm_data_sharing=LLMSharing(**row.llm_data_sharing),
            paused_at=row.paused_at,
            paused_by=row.paused_by,
            pause_reason=row.pause_reason,
            stop_reason=row.stop_reason,
        )
