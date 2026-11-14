"""Domain errors mapped to stable API codes.

Each carries a machine-readable ``code`` so the HTTP layer never invents one, and so the
docs/API_SPECIFICATION.md 2 error table stays the single source of truth.
"""

from __future__ import annotations


class DomainError(Exception):
    code: str = "DOMAIN_ERROR"
    http_status: int = 400

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


class AuthorizationRequired(DomainError):
    code = "AUTH_REQUIRED"
    http_status = 409


class AuthorizationExpired(DomainError):
    code = "AUTH_EXPIRED"
    http_status = 409


class AuthorizationRevoked(DomainError):
    code = "AUTH_REVOKED"
    http_status = 409


class IntensityNotGranted(DomainError):
    code = "INTENSITY_NOT_GRANTED"
    http_status = 409


class IntensityDisabledByPolicy(DomainError):
    code = "INTENSITY_DISABLED"
    http_status = 409


class ApkInvalid(DomainError):
    code = "APK_INVALID"
    http_status = 422


class ApkTooLarge(DomainError):
    code = "APK_TOO_LARGE"
    http_status = 413


class NotFound(DomainError):
    code = "NOT_FOUND"
    http_status = 404


class ScanStateConflict(DomainError):
    code = "SCAN_STATE_CONFLICT"
    http_status = 409


class GateNotSatisfied(DomainError):
    code = "GATE_NOT_SATISFIED"
    http_status = 409


class MissingEvidence(DomainError):
    code = "MISSING_EVIDENCE"
    http_status = 422


class ValidatorMustDiffer(DomainError):
    code = "VALIDATOR_MUST_DIFFER"
    http_status = 409
