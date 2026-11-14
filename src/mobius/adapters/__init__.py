"""Layer 2: adapters.

Implements the ports declared in ``mobius.core.ports``. Everything that touches I/O - the
database, the event store, model providers, tool binaries - lives here, so Layer 1 stays
testable without any of it.
"""
