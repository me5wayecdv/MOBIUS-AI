"""Explicit disposable-test factory. Never imported/registered by the default API.

The run ID is a non-secret instance correlation value, NOT authentication or
owner permission. It prevents accidentally writing to a default/tunnelled API
that does not deliberately expose this seam. A hostile local service can forge
it; exclusive ownership of the disposable host/DB remains a deployment duty.
"""
from __future__ import annotations
import os
import re
import uuid
from fastapi import HTTPException
from sqlalchemy import select
from ..adapters.models import Base,UserRow
from .deps import get_context

# Check every mapped writable domain table, including events/findings/verdicts,
# graph links and PoC links with composite keys. The identity catalogue is the
# sole exception: a freshly migrated test DB may already contain its stub user.
# New mapped domain tables are included automatically rather than silently missed.
_TABLES=tuple(sorted((mapper.local_table for mapper in Base.registry.mappers
                     if mapper.class_ is not UserRow),key=lambda table:table.name))


def _domain_empty(ctx):
    with ctx.session() as session:
        return not any(session.execute(select(1).select_from(table).limit(1)).first()
                       for table in _TABLES)


def create_canary_app():
    """Only use on a fresh exclusively owned disposable instance, model disabled."""
    run_id=os.environ.get('MOBIUS_CANARY_RUN_ID','')
    worker_id=os.environ.get('MOBIUS_CANARY_WORKER_ID','')
    try:
        if str(uuid.UUID(run_id))!=run_id:raise ValueError
    except ValueError:raise RuntimeError('canonical canary run UUID required') from None
    if re.fullmatch(r'[A-Za-z0-9_.-]{1,128}',worker_id) is None:
        raise RuntimeError('literal canary worker identity required')
    ctx=get_context()
    if ctx.settings.env.lower()!='test' or ctx.model_gateway is not None:
        raise RuntimeError('canary factory requires test environment and disabled model gateway')
    if not _domain_empty(ctx):raise RuntimeError('disposable canary database is not empty')
    from .app import create_app
    app=create_app()
    @app.get('/api/v1/_canary/freshness',include_in_schema=False)
    def freshness():
        if not _domain_empty(ctx):raise HTTPException(status_code=409,detail='canary instance no longer empty')
        return {'kind':'disposable-canary-v1','run_id':run_id,'worker_id':worker_id,'empty':True}
    return app
