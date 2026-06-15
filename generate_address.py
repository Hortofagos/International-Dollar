# Compatibility launcher for IND wallet address generation.

from ind import address_generation as _impl
from ind.address_generation import *  # noqa: F401,F403

if __name__ == "__main__":
    _impl.main()
