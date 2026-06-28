# Environment parsing helpers shared by CLI, node, and operator code.

import os

TRUE_VALUES = {"1", "true", "yes", "on"}
FALSE_VALUES = {"0", "false", "no", "off"}


def enabled(name):
    return os.environ.get(name, "").strip().lower() in TRUE_VALUES


def disabled(name):
    return os.environ.get(name, "").strip().lower() in FALSE_VALUES


def bool_value(name, default=False):
    raw = os.environ.get(name)
    if raw is None:
        return bool(default)
    return raw.strip().lower() in TRUE_VALUES


def int_value(name, default, minimum=None, maximum=None):
    try:
        result = int(os.environ.get(name, default))
    except (TypeError, ValueError):
        result = int(default)
    if minimum is not None:
        result = max(int(minimum), result)
    if maximum is not None:
        result = min(int(maximum), result)
    return result


def float_value(name, default, minimum=None, maximum=None):
    try:
        result = float(os.environ.get(name, default))
    except (TypeError, ValueError):
        result = float(default)
    if minimum is not None:
        result = max(float(minimum), result)
    if maximum is not None:
        result = min(float(maximum), result)
    return result


def list_value(name):
    raw = os.environ.get(name, "").strip()
    if not raw:
        return []
    return [item.strip() for item in raw.replace("\n", ",").split(",") if item.strip()]
