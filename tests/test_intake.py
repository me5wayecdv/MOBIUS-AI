"""Intake is where the legal controls live, so it gets the adversarial tests.

Every refusal below corresponds to a documented requirement: FR-AUTH-2 (no work without an
authorisation), FR-AUTH-3 (authorisation pinned to the artefact), and the intensity ceiling
that keeps v1 static-only.
"""

from __future__ import annotations

import pytest

from mobius.core.enums import InvestigationState
from mobius.services import errors, intake
from mobius.services.artifacts import ArtifactStore
from mobius.services.intake import IntakeService

from conftest import make_apk


@pytest.fixture()
def service(session, store):
    return IntakeService(session, store)


def _authorize(service, app, *, expires, max_intensity=2, sha=None):
    return service.create_authorization(
        apk_sha256=sha or app.sha256,
        target_package="com.example",
        scope_text="Static analysis of the supplied artefact only; no execution.",
        statement="I am authorised to analyse this build.",
        max_intensity=max_intensity,
        granted_by="analyst-1",
        expires_at=expires,
    )


# -- upload ----------------------------------------------------------------------------


def test_upload_records_hash_and_writes_the_artefact(service, store):
    data = make_apk()
    app, created = service.create_application(data, "a.apk", uploaded_by="analyst-1")
    assert created is True
    assert app.sha256 == ArtifactStore.digest(data)
    assert store.exists(app.artifact_key)
    assert store.get(app.artifact_key) == data


def test_reupload_is_idempotent(service):
    data = make_apk()
    first, created_first = service.create_application(data, "a.apk", uploaded_by="u")
    second, created_second = service.create_application(data, "b.apk", uploaded_by="u")
    assert created_first and not created_second
    assert first.id == second.id


def test_rejects_non_zip(service):
    with pytest.raises(errors.ApkInvalid):
        service.create_application(b"not a zip", "a.apk", uploaded_by="u")


def test_rejects_zip_without_a_manifest(service):
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("readme.txt", "hello")
    with pytest.raises(errors.ApkInvalid, match="AndroidManifest"):
        service.create_application(buf.getvalue(), "a.apk", uploaded_by="u")


def test_rejects_empty_upload(service):
    with pytest.raises(errors.ApkInvalid):
        service.create_application(b"", "a.apk", uploaded_by="u")


def test_rejects_oversized_upload(service, monkeypatch):
    monkeypatch.setattr(intake, "MAX_APK_BYTES", 10)
    with pytest.raises(errors.ApkTooLarge):
        service.create_application(make_apk(), "a.apk", uploaded_by="u")


def test_artifact_store_refuses_traversal(store):
    with pytest.raises(ValueError):
        store.path_for("../../etc/passwd")


# -- investigation creation ------------------------------------------------------------


def test_happy_path_opens_and_starts(service, future_iso):
    app, _ = service.create_application(make_apk(), "a.apk", uploaded_by="u")
    auth = _authorize(service, app, expires=future_iso)
    inv = service.create_investigation(
        application_id=app.id, authorization_id=auth.id,
        objective="Determine whether exported components reach a privileged sink.",
        intensity=0, created_by="u",
    )
    assert inv.state is InvestigationState.INTAKE
    service.start(inv.id)
    assert service.get_investigation(inv.id).state is InvestigationState.RECON


def test_authorisation_is_pinned_to_the_artefact(service, future_iso):
    app, _ = service.create_application(make_apk(), "a.apk", uploaded_by="u")
    auth = _authorize(service, app, expires=future_iso, sha="f" * 64)
    with pytest.raises(errors.AuthorizationRequired, match="different APK hash"):
        service.create_investigation(
            application_id=app.id, authorization_id=auth.id,
            objective="Attempt to analyse a build that was never authorised.",
            intensity=0, created_by="u",
        )


def test_expired_authorisation_is_refused(service, past_iso):
    app, _ = service.create_application(make_apk(), "a.apk", uploaded_by="u")
    auth = _authorize(service, app, expires=past_iso)
    with pytest.raises(errors.AuthorizationExpired):
        service.create_investigation(
            application_id=app.id, authorization_id=auth.id,
            objective="Attempt to start after the grant has lapsed.",
            intensity=0, created_by="u",
        )


def test_intensity_above_the_grant_is_refused(service, future_iso):
    app, _ = service.create_application(make_apk(), "a.apk", uploaded_by="u")
    auth = _authorize(service, app, expires=future_iso, max_intensity=0)
    with pytest.raises(errors.IntensityNotGranted):
        service.create_investigation(
            application_id=app.id, authorization_id=auth.id,
            objective="Ask for dynamic behaviour the grant does not cover.",
            intensity=1, created_by="u",
        )


def test_intensity_three_is_disabled_globally(service, future_iso):
    """Even with a grant for intensity 3, v1 refuses: the capability does not exist yet."""
    app, _ = service.create_application(make_apk(), "a.apk", uploaded_by="u")
    auth = _authorize(service, app, expires=future_iso, max_intensity=3)
    with pytest.raises(errors.IntensityDisabledByPolicy):
        service.create_investigation(
            application_id=app.id, authorization_id=auth.id,
            objective="Request invasive instrumentation before it is implemented.",
            intensity=3, created_by="u",
        )


def test_unknown_application_is_not_found(service, future_iso):
    with pytest.raises(errors.NotFound):
        service.create_investigation(
            application_id="app_missing", authorization_id="ath_missing",
            objective="Reference something that does not exist.", intensity=0, created_by="u",
        )


def test_missing_authorisation_is_refused(service):
    app, _ = service.create_application(make_apk(), "a.apk", uploaded_by="u")
    with pytest.raises(errors.AuthorizationRequired):
        service.create_investigation(
            application_id=app.id, authorization_id="ath_missing",
            objective="Start work with no authorisation on file.", intensity=0, created_by="u",
        )


def test_revoked_authorisation_is_refused(service, session, future_iso):
    from mobius.adapters.events import utcnow

    app, _ = service.create_application(make_apk(), "a.apk", uploaded_by="u")
    auth = _authorize(service, app, expires=future_iso)
    row = service.get_authorization(auth.id)
    row.revoked_at = utcnow()
    session.flush()
    with pytest.raises(errors.AuthorizationRevoked):
        service.create_investigation(
            application_id=app.id, authorization_id=auth.id,
            objective="Start work after the grant was withdrawn.", intensity=0, created_by="u",
        )


# -- pause / resume / cancel -----------------------------------------------------------


@pytest.fixture()
def running(service, future_iso):
    app, _ = service.create_application(make_apk(), "a.apk", uploaded_by="u")
    auth = _authorize(service, app, expires=future_iso)
    inv = service.create_investigation(
        application_id=app.id, authorization_id=auth.id,
        objective="Investigate the exported component surface.", intensity=0, created_by="u",
    )
    service.start(inv.id)
    return inv.id


def test_pause_sets_a_flag_and_keeps_the_state(service, running):
    paused = service.pause(running, by="analyst-1", reason="need to check scope")
    assert paused.paused_at is not None
    assert paused.paused_by == "analyst-1"
    assert paused.state is InvestigationState.RECON  # ADR-017: pause is not a state


def test_pause_is_idempotent(service, running):
    first = service.pause(running, by="a")
    second = service.pause(running, by="b")
    assert first.paused_at == second.paused_at
    assert second.paused_by == "a"


def test_resume_clears_the_flag(service, running):
    service.pause(running, by="a")
    resumed = service.resume(running, by="a")
    assert resumed.paused_at is None and resumed.paused_by is None


def test_cancel_is_terminal_and_idempotent(service, running):
    cancelled = service.cancel(running, by="a")
    assert cancelled.state is InvestigationState.CANCELLED
    assert service.cancel(running, by="a").state is InvestigationState.CANCELLED
    with pytest.raises(errors.ScanStateConflict):
        service.pause(running, by="a")



def test_artifact_store_rejects_absolute_and_noncanonical_keys(store):
    for key in ("/etc/passwd", "apk/aa/../secret.apk", "apk/aa/not-a-digest.apk"):
        with pytest.raises(ValueError):
            store.path_for(key)


def test_artifact_store_rejects_a_digest_that_does_not_match_content(store):
    with pytest.raises(ValueError, match="does not match"):
        store.put(b"content", "0" * 64)


def test_artifact_store_verifies_bytes_when_read_back(store):
    payload = b"original evidence"
    key, _ = store.put(payload)
    path = store.path_for(key)
    path.write_bytes(b"tampered evidence")
    with pytest.raises(OSError, match="digest verification"):
        store.get(key)


def test_artifact_store_refuses_symlink_objects(store, tmp_path):
    outside = tmp_path / "outside"
    outside.write_bytes(b"not an artifact")
    digest = ArtifactStore.digest(b"not an artifact")
    key = store.key_for(digest)
    target = store.path_for(key)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.symlink_to(outside)
    with pytest.raises(ValueError, match="symlink"):
        store.path_for(key)
