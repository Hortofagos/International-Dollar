# Compatibility wrapper for wallet-side IND node communication.

from ind import sender_node as _impl

globals().update({name: value for name, value in vars(_impl).items() if not name.startswith("__")})
__all__ = [name for name in globals() if not name.startswith("__") and name != "_impl"]
