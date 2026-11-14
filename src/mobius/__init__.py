"""MOBIUS - an evidence-driven Android security investigation platform.

Layering (see docs/ARCHITECTURE.md 3.1):

  core/       Layer 1 - pure Python. No I/O, no framework imports, no vendor SDK.
  adapters/   Layer 2 - database, event store, model gateways, tool adapters.
  services/   Layer 3 - use cases orchestrating core + adapters.
  api/        Layer 4 - FastAPI delivery.

The import-lint test in tests/test_layering.py enforces that core/ imports nothing
from the layers above it.
"""

__version__ = "0.1.0"
