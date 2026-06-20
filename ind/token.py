"""Public IND bill protocol API.

This module keeps the old `ind_token` surface area while the implementation is
split between bill validation/signing logic and the local SQLite gossip store.
"""

from . import protocol as _protocol
from . import protocol_policy as _protocol_policy
from .store import INDLocalStore as INDLocalStore

globals().update(
    {name: value for name, value in vars(_protocol).items() if not name.startswith("__")}
)


_DISABLED_LEGACY_BILL_API = {
    "create_bill_checkpoint",
    "create_checkpoint_announcement",
    "create_compact_bill",
    "create_compact_transfer",
    "create_conflict_proof",
    "create_receipt",
    "create_receipt_announcement",
    "create_transfer",
    "create_transfer_announcement",
    "make_genesis_token",
    "make_lazy_genesis_token",
    "verify_bill",
    "verify_checkpoint_for_genesis",
    "verify_compact_bill",
    "verify_conflict_proof",
    "verify_genesis",
    "verify_receipt_announcement",
    "verify_token",
    "verify_token_transparency",
}


def _legacy_bill_api_disabled(*_args, **_kwargs):
    raise _protocol.ValidationError(_protocol_policy.legacy_disabled_message("legacy bill API"))


for _name in _DISABLED_LEGACY_BILL_API:
    globals()[_name] = _legacy_bill_api_disabled

__all__ = [
    name
    for name in globals()
    if not name.startswith("__")
    and name
    not in {
        "_protocol",
        "_protocol_policy",
        "_DISABLED_LEGACY_BILL_API",
        "_legacy_bill_api_disabled",
        "_name",
    }
]
