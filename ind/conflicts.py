# Conflict-proof helpers for the active V3 tree.

from . import protocol_policy
from .protocol import CONFLICT_PROOF_TYPE, ValidationError


def _disabled(*_args, **_kwargs):
    raise ValidationError(protocol_policy.legacy_disabled_message("legacy conflict API"))


create_conflict_proof = _disabled
verify_conflict_proof = _disabled

__all__ = [
    "CONFLICT_PROOF_TYPE",
    "create_conflict_proof",
    "verify_conflict_proof",
]
