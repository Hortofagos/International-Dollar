# Compatibility launcher for the IND transparency log operator.

from ind import transparency_server as _impl
from ind.transparency_server import *  # noqa: F401,F403

if __name__ == "__main__":
    _impl.main()
