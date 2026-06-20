# Retired receipt compatibility helpers.

from . import protocol_policy
from .protocol import (
    RECEIPT_ANNOUNCEMENT_TYPE,
    RECEIPT_SIGNATURE_DOMAIN,
    RECEIPT_TYPE,
    ValidationError,
)


def _disabled(*_args, **_kwargs):
    raise ValidationError(protocol_policy.legacy_disabled_message("legacy receipt API"))


create_receipt = _disabled
create_receipt_announcement = _disabled
verify_receipt_announcement = _disabled

__all__ = [
    "RECEIPT_ANNOUNCEMENT_TYPE",
    "RECEIPT_SIGNATURE_DOMAIN",
    "RECEIPT_TYPE",
    "create_receipt",
    "create_receipt_announcement",
    "verify_receipt_announcement",
]
