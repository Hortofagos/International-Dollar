# Transfer helpers for the active V3 tree.

from . import protocol_policy
from .protocol import (
    TRANSFER_ANNOUNCEMENT_TYPE,
    TRANSFER_SIGNATURE_DOMAIN,
    TRANSFER_TYPE,
    ValidationError,
    transfer_hash,
)


def _disabled(*_args, **_kwargs):
    raise ValidationError(protocol_policy.legacy_disabled_message("legacy transfer API"))


create_transfer = _disabled
create_compact_transfer = _disabled
create_transfer_announcement = _disabled
verify_bill = _disabled
verify_token = _disabled
verify_token_transparency = _disabled

__all__ = [
    "TRANSFER_ANNOUNCEMENT_TYPE",
    "TRANSFER_SIGNATURE_DOMAIN",
    "TRANSFER_TYPE",
    "create_transfer",
    "create_compact_transfer",
    "create_transfer_announcement",
    "transfer_hash",
    "verify_bill",
    "verify_token",
    "verify_token_transparency",
]
