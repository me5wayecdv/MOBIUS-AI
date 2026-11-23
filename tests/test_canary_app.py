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


@pytest.mark.parametrize('leftover',['events','findings','verdicts','graph_node_evidence','poc_run_evidence'])
def test_any_leftover_domain_row_refuses_even_if_parent_tables_are_empty(monkeypatch,ctx,leftover):
    """Orphan-row sentinel simulation checks each existence query, no FK bypass."""
    from mobius.api import canary_app
    config(monkeypatch)
    assert leftover in {t.name for t in canary_app._TABLES}
    class Result:
        def __init__(self,present):self.present=present
        def first(self):return (1,) if self.present else None
    class Session:
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def execute(self,statement):return Result(statement.get_final_froms()[0].name==leftover)
    monkeypatch.setattr(ctx,'session',lambda:Session())
    with pytest.raises(RuntimeError,match='not empty'):create_canary_app()


def test_freshness_covers_all_mapped_domain_tables():
    from mobius.api.canary_app import _TABLES
    from mobius.adapters.models import Base
    assert {t.name for t in _TABLES}==set(Base.metadata.tables)-{'users'}


def test_disabled_provider_constructs_no_gateway():
    from mobius.services.model_provider import create_model_gateway
    assert create_model_gateway('disabled',base_url='http://invalid.local',model='unused') is None
