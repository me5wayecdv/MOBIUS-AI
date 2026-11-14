"""Layer 3: use cases.

Orchestrates Layer 1 (pure domain) with Layer 2 (adapters). This is the only layer that
writes rows, and it does so with explicit flushes in dependency order - see the note in
mobius.services.intake.
"""
