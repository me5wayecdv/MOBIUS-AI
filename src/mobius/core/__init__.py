"""Layer 1: the domain core.

Contains the models, the investigation state machine, the confirmation gates and the
frontier scorer. Everything here is pure functions and data - no I/O, no database, no
network, no model client. That is what makes it testable without infrastructure.
"""
