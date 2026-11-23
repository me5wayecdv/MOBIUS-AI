"""Explicit factory-only freshness heuristic, no default API exposure."""
import uuid
import pytest
from fastapi.testclient import TestClient
from conftest import make_apk
from mobius.api.canary_app import create_canary_app
from mobius.services.intake import IntakeService


def config(monkeypatch):
    run_id=str(uuid.uuid4())
    monkeypatch.setenv('MOBIUS_CANARY_RUN_ID',run_id)
    monkeypatch.setenv('MOBIUS_CANARY_WORKER_ID','unit-worker')
    return run_id


def test_explicit_factory_empty_then_nonempty_refuses(ctx,monkeypatch):
    rid=config(monkeypatch)
    app=create_canary_app()
    with TestClient(app) as client:
        result=client.get('/api/v1/_canary/freshness')
        assert result.json()=={'kind':'disposable-canary-v1','run_id':rid,'worker_id':'unit-worker','empty':True}
        with ctx.session() as session:
            IntakeService(session,ctx.store).create_application(make_apk(),'unit.apk',uploaded_by='unit')
            session.commit()
        assert client.get('/api/v1/_canary/freshness').status_code==409
    with pytest.raises(RuntimeError,match='not empty'):create_canary_app()


@pytest.mark.parametrize('kind',['missing_run','non_test','model'])
def test_factory_refuses_unscoped_configuration(ctx,monkeypatch,kind):
    config(monkeypatch)
    if kind=='missing_run':monkeypatch.delenv('MOBIUS_CANARY_RUN_ID')
    elif kind=='non_test':
        from dataclasses import replace
        ctx.settings=replace(ctx.settings,env='development')
    else:ctx.model_gateway=object()
    with pytest.raises(RuntimeError):create_canary_app()
