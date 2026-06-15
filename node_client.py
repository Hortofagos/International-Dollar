# Compatibility launcher for the IND desktop gossip node.

from ind import node_client as _impl

globals().update({name: value for name, value in vars(_impl).items() if not name.startswith("__")})
__all__ = [name for name in globals() if not name.startswith("__") and name != "_impl"]

if __name__ == "__main__":
    _impl.main()
