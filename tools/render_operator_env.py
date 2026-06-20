#!/usr/bin/env python3
"""Render strict IND operator-witness environment from an operator set JSON file."""

import argparse
import json
import shlex
import sys
from pathlib import Path
from urllib.parse import urlparse

ROOT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_OPERATOR_SET = ROOT_DIR / "testnet" / "operator_set.testnet.json"


class OperatorSetError(RuntimeError):
    pass


def _as_list(value):
    if value is None:
        return []
    if not isinstance(value, list):
        raise OperatorSetError("operator mirrors and proof_archives must be lists")
    return [str(item).strip() for item in value if str(item).strip()]


def _http_origin(value):
    parsed = urlparse(str(value).strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    return f"{parsed.scheme}://{parsed.hostname.lower()}:{port}"


def load_operator_set(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise OperatorSetError("operator set must be a JSON object")
    operators = data.get("operators")
    if not isinstance(operators, list) or not operators:
        raise OperatorSetError("operator set must include at least one operator")
    min_root_mirrors = int(data.get("min_root_mirrors", 2))
    normalized = []
    names = set()
    urls = set()
    keys = set()
    for index, item in enumerate(operators):
        if not isinstance(item, dict):
            raise OperatorSetError(f"operator {index} must be an object")
        name = str(item.get("name") or f"operator-{index + 1}").strip()
        url = str(item.get("url") or "").strip().rstrip("/")
        public_key = str(item.get("public_key") or "").strip()
        mirrors = _as_list(item.get("mirrors"))
        archives = _as_list(item.get("proof_archives"))
        if not url:
            raise OperatorSetError(f"{name} is missing append url")
        if not public_key:
            raise OperatorSetError(f"{name} is missing public_key")
        if len(mirrors) < min_root_mirrors:
            raise OperatorSetError(
                f"{name} has {len(mirrors)} mirror(s), needs {min_root_mirrors}"
            )
        operator_origin = _http_origin(url)
        mirror_origins = {_http_origin(mirror) for mirror in mirrors}
        if operator_origin and operator_origin in mirror_origins:
            raise OperatorSetError(
                f"{name} mirror must not share the operator append HTTP origin"
            )
        if len(archives) < min_root_mirrors:
            raise OperatorSetError(
                f"{name} has {len(archives)} proof archive(s), needs {min_root_mirrors}"
            )
        archive_origins = {_http_origin(archive) for archive in archives}
        if operator_origin and operator_origin in archive_origins:
            raise OperatorSetError(
                f"{name} proof archive must not share the operator append HTTP origin"
            )
        if name in names or url in urls or public_key in keys:
            raise OperatorSetError(f"{name} duplicates another operator identity")
        names.add(name)
        urls.add(url)
        keys.add(public_key)
        normalized.append(
            {
                "name": name,
                "url": url,
                "public_key": public_key,
                "mirrors": mirrors,
                "proof_archives": archives,
            }
        )
    return {
        "network": str(data.get("network") or "testnet"),
        "min_root_mirrors": min_root_mirrors,
        "operators": normalized,
    }


def env_from_operator_set(operator_set):
    operators = [
        {
            "url": item["url"],
            "public_key": item["public_key"],
            "mirrors": item["mirrors"],
            "proof_archives": item["proof_archives"],
        }
        for item in operator_set["operators"]
    ]
    count = len(operators)
    return {
        "IND_NETWORK": operator_set["network"],
        "IND_REQUIRE_TRANSPARENCY_LOG": "1",
        "IND_SUBMIT_TO_TRANSPARENCY_LOG": "1",
        "IND_LOG_OPERATORS": json.dumps(operators, sort_keys=True, separators=(",", ":")),
        "IND_OPERATOR_FINALITY_MIN_PROOFS": str(count),
        "IND_LOG_MIN_MIRRORS": str(operator_set["min_root_mirrors"]),
        "IND_SETTLEMENT_QUORUM_ENABLED": "1",
        "IND_SETTLEMENT_REQUIRE_ALL_CONFIGURED_PEERS": "1",
        "IND_TRANSPARENCY_SUBMIT_ASYNC": "1",
    }


def _systemd_quote(value):
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _systemd_envfile_quote(value):
    value = str(value)
    if "'" in value:
        raise OperatorSetError("systemd EnvironmentFile values may not contain single quotes")
    return "'" + value + "'"


def render_env(env, output_format):
    if output_format == "json":
        return json.dumps(env, indent=2, sort_keys=True) + "\n"
    if output_format == "powershell":
        return "".join(f"$env:{key} = {json.dumps(value)}\n" for key, value in sorted(env.items()))
    if output_format == "systemd":
        return "".join(f"Environment={key}={_systemd_quote(value)}\n" for key, value in sorted(env.items()))
    if output_format == "systemd-envfile":
        return "".join(f"{key}={_systemd_envfile_quote(value)}\n" for key, value in sorted(env.items()))
    if output_format == "shell":
        return "".join(f"export {key}={shlex.quote(value)}\n" for key, value in sorted(env.items()))
    raise OperatorSetError(f"unsupported output format: {output_format}")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operator-set", default=str(DEFAULT_OPERATOR_SET))
    parser.add_argument(
        "--format",
        choices=("json", "powershell", "shell", "systemd", "systemd-envfile"),
        default="json",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    operator_set = load_operator_set(args.operator_set)
    sys.stdout.write(render_env(env_from_operator_set(operator_set), args.format))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
