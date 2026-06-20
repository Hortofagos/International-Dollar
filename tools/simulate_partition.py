#!/usr/bin/env python3
"""Legacy partition simulator removed.

Use ``tools/v3_double_spend_drill.py --dry-run`` against stored BillV3 data for
native V3 conflict construction.
"""

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from ind import protocol_policy


def main():
    raise SystemExit(
        protocol_policy.legacy_disabled_message(
            "legacy partition simulator; use tools/v3_double_spend_drill.py --dry-run"
        )
    )


if __name__ == "__main__":
    main()
