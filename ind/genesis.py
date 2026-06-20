# Genesis helpers for the active V3 tree.

from . import protocol_policy
from .protocol import (
    GENESIS_MANIFEST_TYPE,
    GENESIS_SIGNATURE_DOMAIN,
    TOTAL_SUPPLY,
    ValidationError,
    genesis_hash,
    genesis_manifest_hash,
)


def _disabled(*_args, **_kwargs):
    raise ValidationError(protocol_policy.legacy_disabled_message("legacy genesis API"))


make_denomination_ranges = _disabled
make_genesis_manifest = _disabled
make_genesis_token = _disabled
make_lazy_genesis_token = _disabled
verify_genesis = _disabled
verify_genesis_manifest = _disabled

__all__ = [
    "GENESIS_MANIFEST_TYPE",
    "GENESIS_SIGNATURE_DOMAIN",
    "TOTAL_SUPPLY",
    "genesis_hash",
    "genesis_manifest_hash",
    "make_denomination_ranges",
    "make_genesis_manifest",
    "make_genesis_token",
    "make_lazy_genesis_token",
    "verify_genesis",
    "verify_genesis_manifest",
]
