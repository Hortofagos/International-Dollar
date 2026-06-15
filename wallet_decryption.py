# Compatibility wrapper for IND wallet decryption.

from ind import wallet_decryption as _impl

globals().update({name: value for name, value in vars(_impl).items() if not name.startswith("__")})
__all__ = [name for name in globals() if not name.startswith("__") and name != "_impl"]
