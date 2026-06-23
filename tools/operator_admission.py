#!/usr/bin/env python3
"""Create and verify IND transparency-operator admission artifacts.

The admission path is intentionally two-step:

1. A candidate signs an admission bundle with the operator key they want to run.
2. A maintainer signs an operator-set update after mirror/auditor burn-in passes.

Running a gossip node stays permissionless. This tool only governs admission into
the append-capable transparency-operator quorum.
"""

import argparse
import base64
import copy
import json
import os
import sys
import time
import urllib.parse
import urllib.request
from hashlib import sha3_256
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import log_client
from ind import keys_v3
from ind import protocol as ind_token
from tools import render_operator_env

BUNDLE_TYPE = "ind.operator_admission_bundle.v3"
UPDATE_TYPE = "ind.operator_set_update.v3"
BUNDLE_SIGNATURE_DOMAIN = "IND_OPERATOR_ADMISSION_BUNDLE_V3"
UPDATE_SIGNATURE_DOMAIN = "IND_OPERATOR_SET_UPDATE_V3"
SIGNATURE_ALGORITHM = "ED25519_BASE85"
DEFAULT_OPERATOR_SET = ROOT_DIR / "testnet" / "operator_set.testnet.json"
USER_AGENT = "International-Dollar-operator-admission/1"

VALID_STAGES = {"gui_node", "candidate_mirror", "burn_in_passed"}
VALID_STATUSES = {"unknown", "pending", "running", "passed", "failed"}


class OperatorAdmissionError(ValueError):
    pass


def canonical_json(data):
    return ind_token.canonical_json(data)


def canonical_bytes(data):
    return canonical_json(data).encode("utf-8")


def record_hash(data):
    return sha3_256(canonical_bytes(data)).hexdigest()


def _atomic_write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(
        json.dumps(data, sort_keys=True, indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    os.replace(tmp, path)


def _read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise OperatorAdmissionError(f"{path} is not valid JSON: {exc}") from exc


def _read_private_key(path):
    text = Path(path).read_text(encoding="utf-8").strip()
    if not text.startswith(keys_v3.PRIVATE_KEY_PREFIX):
        raise OperatorAdmissionError("private key file must contain one indsk3 key")
    return text


def _write_or_print(path, data):
    if path:
        _atomic_write_json(path, data)
    else:
        print(json.dumps(data, sort_keys=True, indent=2, ensure_ascii=True))


def _split_many(values):
    result = []
    for value in values or []:
        for item in str(value).replace("\n", ",").split(","):
            item = item.strip()
            if item:
                result.append(item)
    return result


def _dedupe(items):
    result = []
    seen = set()
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _require_fields(record, fields, label):
    missing = sorted(field for field in fields if field not in record)
    if missing:
        raise OperatorAdmissionError(f"{label} is missing required fields: {', '.join(missing)}")


def _normalize_http_url(value, label):
    value = str(value or "").strip().rstrip("/")
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise OperatorAdmissionError(f"{label} must be an http(s) URL")
    if parsed.fragment:
        raise OperatorAdmissionError(f"{label} must not contain a URL fragment")
    return value


def _http_origin(value):
    parsed = urllib.parse.urlparse(str(value).strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    return f"{parsed.scheme}://{parsed.hostname.lower()}:{port}"


def _origin_count(urls):
    return len({_http_origin(item) for item in urls if _http_origin(item)})


def _join_url(base, suffix):
    return urllib.parse.urljoin(str(base).rstrip("/") + "/", str(suffix).lstrip("/"))


def _fetch_json(url, timeout=10):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def _unsigned_bundle(bundle):
    unsigned = copy.deepcopy(bundle)
    unsigned.pop("candidate_signature", None)
    return unsigned


def _unsigned_update(update):
    unsigned = copy.deepcopy(update)
    unsigned.pop("signature", None)
    return unsigned


def _sign_payload(private_key, payload):
    return base64.b85encode(keys_v3.sign(private_key, payload)).decode("ascii")


def _verify_signature(public_key, signature, payload):
    try:
        signature_bytes = base64.b85decode(str(signature).strip().encode("ascii"))
    except Exception:
        return False
    return keys_v3.verify(public_key, signature_bytes, payload)


def _signature_payload(domain, record):
    return ind_token.signature_payload(domain, record)


def normalize_operator_record(operator, *, min_root_mirrors=2):
    if not isinstance(operator, dict):
        raise OperatorAdmissionError("operator must be a JSON object")
    _require_fields(
        operator,
        {"name", "url", "public_key", "mirrors", "proof_archives"},
        "operator",
    )
    name = str(operator.get("name", "")).strip()
    if not name:
        raise OperatorAdmissionError("operator name is required")
    url = _normalize_http_url(operator.get("url"), "operator append URL")
    public_key = str(operator.get("public_key", "")).strip()
    try:
        keys_v3.decode_public_key(public_key)
    except Exception as exc:
        raise OperatorAdmissionError("operator public_key must be an indpk3 key") from exc
    mirrors = _dedupe(_normalize_http_url(item, "operator mirror") for item in operator["mirrors"])
    archives = _dedupe(
        _normalize_http_url(item, "operator proof archive") for item in operator["proof_archives"]
    )
    min_root_mirrors = int(min_root_mirrors)
    if len(mirrors) < min_root_mirrors:
        raise OperatorAdmissionError(
            f"operator has {len(mirrors)} mirror(s), needs {min_root_mirrors}"
        )
    if len(archives) < min_root_mirrors:
        raise OperatorAdmissionError(
            f"operator has {len(archives)} proof archive(s), needs {min_root_mirrors}"
        )
    operator_origin = _http_origin(url)
    if operator_origin in {_http_origin(item) for item in mirrors}:
        raise OperatorAdmissionError("operator mirror must not share append API origin")
    if operator_origin in {_http_origin(item) for item in archives}:
        raise OperatorAdmissionError("operator proof archive must not share append API origin")
    if _origin_count(mirrors) < min_root_mirrors:
        raise OperatorAdmissionError("operator mirrors must use independent HTTP origins")
    if _origin_count(archives) < min_root_mirrors:
        raise OperatorAdmissionError("operator proof archives must use independent HTTP origins")
    return {
        "name": name,
        "url": url,
        "public_key": public_key,
        "mirrors": mirrors,
        "proof_archives": archives,
    }


def load_operator_set(path=DEFAULT_OPERATOR_SET):
    return render_operator_env.load_operator_set(path)


def _operator_set_data(operator_set):
    return {
        "network": str(operator_set.get("network") or "testnet"),
        "min_root_mirrors": int(operator_set.get("min_root_mirrors", 2)),
        "operator_append_fanout": int(
            operator_set.get("operator_append_fanout")
            or render_operator_env.DEFAULT_OPERATOR_APPEND_FANOUT
        ),
        "operator_core_domains": list(
            operator_set.get("operator_core_domains")
            or render_operator_env.DEFAULT_OPERATOR_CORE_DOMAINS
        ),
        "operators": list(operator_set.get("operators") or []),
    }


def operator_set_with_candidate(operator_set, operator):
    base = _operator_set_data(operator_set)
    min_root_mirrors = int(base.get("min_root_mirrors", 2))
    candidate = normalize_operator_record(operator, min_root_mirrors=min_root_mirrors)
    names = {item["name"] for item in base["operators"]}
    urls = {item["url"].rstrip("/") for item in base["operators"]}
    keys = {item["public_key"] for item in base["operators"]}
    if candidate["name"] in names:
        raise OperatorAdmissionError(f"operator name already exists: {candidate['name']}")
    if candidate["url"].rstrip("/") in urls:
        raise OperatorAdmissionError(f"operator append URL already exists: {candidate['url']}")
    if candidate["public_key"] in keys:
        raise OperatorAdmissionError("operator public_key already exists")
    proposed = {
        "network": base["network"],
        "min_root_mirrors": min_root_mirrors,
        "operator_append_fanout": base["operator_append_fanout"],
        "operator_core_domains": base["operator_core_domains"],
        "operators": base["operators"] + [candidate],
    }
    try:
        return render_operator_env.normalize_operator_set(proposed)
    except render_operator_env.OperatorSetError as exc:
        raise OperatorAdmissionError(str(exc)) from exc


def _artifact_ref(path):
    if not path:
        return None
    path = Path(path)
    data = path.read_bytes()
    artifact = {
        "path": path.name,
        "sha3_256": sha3_256(data).hexdigest(),
        "size_bytes": len(data),
    }
    if path.suffix.lower() == ".json":
        try:
            parsed = json.loads(data.decode("utf-8"))
            if isinstance(parsed, dict):
                artifact["status"] = str(parsed.get("status", "")).strip() or "provided"
                artifact["summary"] = str(parsed.get("summary", "")).strip()
        except Exception:
            pass
    return artifact


def make_candidate_bundle(
    *,
    name,
    network,
    public_key,
    append_url,
    mirrors,
    proof_archives,
    peers=None,
    node_port=0,
    stage="candidate_mirror",
    uptime_status="unknown",
    audit_status="unknown",
    uptime_report_file=None,
    audit_report_file=None,
    created_at=None,
):
    if stage not in VALID_STAGES:
        raise OperatorAdmissionError(f"unsupported admission stage: {stage}")
    if uptime_status not in VALID_STATUSES:
        raise OperatorAdmissionError(f"unsupported uptime status: {uptime_status}")
    if audit_status not in VALID_STATUSES:
        raise OperatorAdmissionError(f"unsupported audit status: {audit_status}")
    operator = normalize_operator_record(
        {
            "name": name,
            "url": append_url,
            "public_key": public_key,
            "mirrors": mirrors,
            "proof_archives": proof_archives,
        }
    )
    uptime_artifact = _artifact_ref(uptime_report_file)
    audit_artifact = _artifact_ref(audit_report_file)
    return {
        "type": BUNDLE_TYPE,
        "version": 1,
        "network": str(network or "testnet"),
        "created_at": int(created_at or time.time()),
        "admission_stage": stage,
        "operator": operator,
        "candidate_node": {
            "tcp_port": int(node_port or 0),
            "peers": _dedupe(str(peer).strip() for peer in (peers or []) if str(peer).strip()),
        },
        "uptime_proof": {
            "status": uptime_status,
            "artifact": uptime_artifact,
        },
        "audit_report": {
            "status": audit_status,
            "artifact": audit_artifact,
        },
        "candidate_commitments": [
            "run as a normal GUI/gossip node before seeking operator admission",
            "run as a mirror/auditor before append-capable promotion",
            "publish at least two independent root mirrors",
            "publish at least two independent proof archive mirrors",
            "accept append-capable activation only through a signed operator-set update",
        ],
    }


def sign_candidate_bundle(bundle, private_key):
    signed = copy.deepcopy(bundle)
    public_key = signed["operator"]["public_key"]
    derived_public_key = keys_v3.generate_keypair(keys_v3.decode_private_key(private_key))[2]
    if derived_public_key != public_key:
        raise OperatorAdmissionError("candidate private key does not match operator public_key")
    signed["candidate_signing_public_key"] = public_key
    signed["candidate_signature_algorithm"] = SIGNATURE_ALGORITHM
    payload = _signature_payload(BUNDLE_SIGNATURE_DOMAIN, _unsigned_bundle(signed))
    signed["candidate_signature"] = _sign_payload(private_key, payload)
    return signed


def verify_candidate_signature(bundle):
    _require_fields(
        bundle,
        {"candidate_signing_public_key", "candidate_signature_algorithm", "candidate_signature"},
        "candidate bundle",
    )
    public_key = str(bundle.get("candidate_signing_public_key", "")).strip()
    if public_key != str(bundle.get("operator", {}).get("public_key", "")).strip():
        raise OperatorAdmissionError("candidate signing key must match operator public_key")
    if bundle.get("candidate_signature_algorithm") != SIGNATURE_ALGORITHM:
        raise OperatorAdmissionError("candidate bundle uses an unsupported signature algorithm")
    payload = _signature_payload(BUNDLE_SIGNATURE_DOMAIN, _unsigned_bundle(bundle))
    if not _verify_signature(public_key, bundle["candidate_signature"], payload):
        raise OperatorAdmissionError("candidate bundle signature is invalid")
    return True


def _add_check(checks, name, ok, detail=""):
    checks.append({"name": name, "ok": bool(ok), "detail": str(detail)})


def _probe_live_operator(operator):
    checks = []
    root_url = _join_url(operator["url"], "v3/root")
    root = _fetch_json(root_url)
    log_client.verify_signed_root(root, operator_public_key=operator["public_key"])
    _add_check(
        checks,
        "append_api_root",
        root.get("operator_public_key") == operator["public_key"],
        root_url,
    )
    for mirror in operator["mirrors"]:
        mirror_url = _join_url(mirror, "latest.json")
        mirrored = _fetch_json(mirror_url)
        log_client.verify_signed_root(mirrored, operator_public_key=operator["public_key"])
        _add_check(checks, "mirror_latest", True, mirror_url)
    for archive in operator["proof_archives"]:
        archive_url = _join_url(archive, "manifest.json")
        manifest = _fetch_json(archive_url)
        signed_root = manifest.get("signed_root", {})
        log_client.verify_signed_root(signed_root, operator_public_key=operator["public_key"])
        _add_check(checks, "proof_archive_manifest", True, archive_url)
    return checks


def verify_candidate_bundle(
    bundle,
    *,
    operator_set=None,
    require_signature=True,
    require_burn_in=False,
    require_live=False,
):
    if not isinstance(bundle, dict):
        raise OperatorAdmissionError("candidate bundle must be a JSON object")
    _require_fields(
        bundle,
        {"type", "version", "network", "admission_stage", "operator"},
        "candidate bundle",
    )
    if bundle["type"] != BUNDLE_TYPE or int(bundle["version"]) != 1:
        raise OperatorAdmissionError("unsupported candidate bundle version")
    stage = str(bundle.get("admission_stage", "")).strip()
    if stage not in VALID_STAGES:
        raise OperatorAdmissionError("candidate bundle has an unsupported admission stage")
    min_root_mirrors = 2
    if operator_set:
        min_root_mirrors = int(operator_set.get("min_root_mirrors", 2))
        if str(operator_set.get("network", "")) != str(bundle.get("network", "")):
            raise OperatorAdmissionError("candidate network does not match operator set")
    operator = normalize_operator_record(bundle["operator"], min_root_mirrors=min_root_mirrors)
    checks = []
    _add_check(checks, "operator_shape", True, "append URL, key, mirrors, and archives are present")
    if require_signature:
        verify_candidate_signature(bundle)
        _add_check(checks, "candidate_signature", True, "operator key signed the bundle")
    if require_burn_in:
        uptime_status = str(bundle.get("uptime_proof", {}).get("status", "unknown"))
        audit_status = str(bundle.get("audit_report", {}).get("status", "unknown"))
        if stage != "burn_in_passed":
            raise OperatorAdmissionError("candidate must complete mirror/auditor burn-in first")
        if uptime_status != "passed" or audit_status != "passed":
            raise OperatorAdmissionError(
                "candidate bundle must include passed uptime and audit status"
            )
        _add_check(checks, "burn_in", True, "uptime and audit status are passed")
    if operator_set:
        operator_set_with_candidate(operator_set, operator)
        _add_check(
            checks, "operator_set_candidate", True, "candidate can be appended without duplicates"
        )
    if require_live:
        try:
            checks.extend(_probe_live_operator(operator))
        except Exception as exc:
            raise OperatorAdmissionError(f"live operator probe failed: {exc}") from exc
    return {
        "ok": True,
        "bundle_hash": record_hash(bundle),
        "network": str(bundle["network"]),
        "operator": operator,
        "checks": checks,
    }


def sign_operator_set_update(update, private_key, public_key):
    signed = copy.deepcopy(update)
    signed["signing_public_key"] = str(public_key).strip()
    signed["signature_algorithm"] = SIGNATURE_ALGORITHM
    payload = _signature_payload(UPDATE_SIGNATURE_DOMAIN, _unsigned_update(signed))
    signed["signature"] = _sign_payload(private_key, payload)
    return signed


def make_operator_set_update(
    operator_set,
    bundle,
    *,
    signing_private_key,
    signing_public_key,
    created_at=None,
    require_burn_in=True,
):
    verify_candidate_bundle(
        bundle,
        operator_set=operator_set,
        require_signature=True,
        require_burn_in=require_burn_in,
    )
    proposed = operator_set_with_candidate(operator_set, bundle["operator"])
    current = _operator_set_data(render_operator_env.normalize_operator_set(operator_set))
    update = {
        "type": UPDATE_TYPE,
        "version": 1,
        "network": current["network"],
        "action": "add_operator",
        "created_at": int(created_at or time.time()),
        "candidate_bundle_hash": record_hash(bundle),
        "previous_operator_set_hash": record_hash(current),
        "proposed_operator_set_hash": record_hash(proposed),
        "candidate_operator": bundle["operator"],
        "proposed_operator_set": proposed,
        "burn_in_required": bool(require_burn_in),
    }
    return sign_operator_set_update(update, signing_private_key, signing_public_key)


def verify_operator_set_update(update, operator_set, bundle, trusted_signing_keys):
    if not isinstance(update, dict):
        raise OperatorAdmissionError("operator-set update must be a JSON object")
    _require_fields(
        update,
        {
            "type",
            "version",
            "network",
            "action",
            "candidate_bundle_hash",
            "previous_operator_set_hash",
            "proposed_operator_set_hash",
            "candidate_operator",
            "proposed_operator_set",
            "signing_public_key",
            "signature_algorithm",
            "signature",
        },
        "operator-set update",
    )
    if update["type"] != UPDATE_TYPE or int(update["version"]) != 1:
        raise OperatorAdmissionError("unsupported operator-set update version")
    if update["action"] != "add_operator":
        raise OperatorAdmissionError("unsupported operator-set update action")
    signing_public_key = str(update["signing_public_key"]).strip()
    trusted = set(_split_many(trusted_signing_keys))
    if signing_public_key not in trusted:
        raise OperatorAdmissionError("operator-set update was signed by an untrusted key")
    if update["signature_algorithm"] != SIGNATURE_ALGORITHM:
        raise OperatorAdmissionError("operator-set update uses an unsupported signature algorithm")
    payload = _signature_payload(UPDATE_SIGNATURE_DOMAIN, _unsigned_update(update))
    if not _verify_signature(signing_public_key, update["signature"], payload):
        raise OperatorAdmissionError("operator-set update signature is invalid")

    current = _operator_set_data(render_operator_env.normalize_operator_set(operator_set))
    if str(update["network"]) != str(current["network"]):
        raise OperatorAdmissionError("operator-set update network does not match current set")
    if update["previous_operator_set_hash"] != record_hash(current):
        raise OperatorAdmissionError("operator-set update does not match the current operator set")
    if update["candidate_bundle_hash"] != record_hash(bundle):
        raise OperatorAdmissionError("operator-set update does not match the candidate bundle")
    verify_candidate_bundle(
        bundle,
        operator_set=operator_set,
        require_signature=True,
        require_burn_in=bool(update.get("burn_in_required", True)),
    )
    proposed = operator_set_with_candidate(operator_set, bundle["operator"])
    if record_hash(proposed) != update["proposed_operator_set_hash"]:
        raise OperatorAdmissionError("operator-set update proposed hash is wrong")
    if canonical_json(proposed) != canonical_json(update["proposed_operator_set"]):
        raise OperatorAdmissionError("operator-set update proposed set is not canonical")
    return {
        "ok": True,
        "update_hash": record_hash(update),
        "network": current["network"],
        "operator_count": len(proposed["operators"]),
        "proposed_operator_set": proposed,
    }


def _load_operator_set_json(path):
    return render_operator_env.normalize_operator_set(_read_json(path))


def _print_report(report, json_output=False):
    if json_output:
        print(json.dumps(report, sort_keys=True, indent=2, ensure_ascii=True))
        return
    print(f"PASS: {report.get('operator', {}).get('name') or report.get('network')}")
    for check in report.get("checks", []):
        status = "ok" if check["ok"] else "failed"
        print(f"- {check['name']}: {status} {check['detail']}".rstrip())


def command_candidate_bundle(args):
    bundle = make_candidate_bundle(
        name=args.name,
        network=args.network,
        public_key=args.public_key,
        append_url=args.append_url,
        mirrors=_split_many(args.mirror),
        proof_archives=_split_many(args.proof_archive),
        peers=_split_many(args.peer),
        node_port=args.node_port,
        stage=args.stage,
        uptime_status=args.uptime_status,
        audit_status=args.audit_status,
        uptime_report_file=args.uptime_report_file,
        audit_report_file=args.audit_report_file,
        created_at=args.created_at,
    )
    if args.private_key_file:
        bundle = sign_candidate_bundle(bundle, _read_private_key(args.private_key_file))
    _write_or_print(args.output, bundle)
    return 0


def command_verify_bundle(args):
    operator_set = _load_operator_set_json(args.operator_set) if args.operator_set else None
    report = verify_candidate_bundle(
        _read_json(args.bundle),
        operator_set=operator_set,
        require_signature=not args.allow_unsigned,
        require_burn_in=args.require_burn_in,
        require_live=args.require_live,
    )
    _print_report(report, json_output=args.json)
    return 0


def command_propose_update(args):
    operator_set = _load_operator_set_json(args.operator_set)
    bundle = _read_json(args.bundle)
    update = make_operator_set_update(
        operator_set,
        bundle,
        signing_private_key=_read_private_key(args.signing_private_key_file),
        signing_public_key=args.signing_public_key,
        created_at=args.created_at,
        require_burn_in=not args.allow_pending_burn_in,
    )
    _write_or_print(args.output, update)
    return 0


def command_verify_update(args):
    report = verify_operator_set_update(
        _read_json(args.update),
        _load_operator_set_json(args.operator_set),
        _read_json(args.bundle),
        _split_many(args.trusted_signing_key),
    )
    _print_report(report, json_output=args.json)
    return 0


def command_apply_update(args):
    report = verify_operator_set_update(
        _read_json(args.update),
        _load_operator_set_json(args.operator_set),
        _read_json(args.bundle),
        _split_many(args.trusted_signing_key),
    )
    if args.output:
        _atomic_write_json(args.output, report["proposed_operator_set"])
    elif args.in_place:
        _atomic_write_json(args.operator_set, report["proposed_operator_set"])
    else:
        raise OperatorAdmissionError("apply-update requires --output or --in-place")
    _print_report(report, json_output=args.json)
    return 0


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    bundle = sub.add_parser("candidate-bundle", help="write a candidate admission bundle")
    bundle.add_argument("--name", required=True)
    bundle.add_argument("--network", default="testnet")
    bundle.add_argument("--public-key", required=True)
    bundle.add_argument("--append-url", required=True)
    bundle.add_argument("--mirror", action="append", required=True)
    bundle.add_argument("--proof-archive", action="append", required=True)
    bundle.add_argument("--peer", action="append")
    bundle.add_argument("--node-port", type=int, default=0)
    bundle.add_argument("--stage", choices=sorted(VALID_STAGES), default="candidate_mirror")
    bundle.add_argument("--uptime-status", choices=sorted(VALID_STATUSES), default="unknown")
    bundle.add_argument("--audit-status", choices=sorted(VALID_STATUSES), default="unknown")
    bundle.add_argument("--uptime-report-file")
    bundle.add_argument("--audit-report-file")
    bundle.add_argument("--private-key-file")
    bundle.add_argument("--created-at", type=int)
    bundle.add_argument("--output")
    bundle.set_defaults(func=command_candidate_bundle)

    verify_bundle = sub.add_parser("verify-bundle", help="verify a candidate bundle")
    verify_bundle.add_argument("bundle")
    verify_bundle.add_argument("--operator-set", default=str(DEFAULT_OPERATOR_SET))
    verify_bundle.add_argument("--allow-unsigned", action="store_true")
    verify_bundle.add_argument("--require-burn-in", action="store_true")
    verify_bundle.add_argument("--require-live", action="store_true")
    verify_bundle.add_argument("--json", action="store_true")
    verify_bundle.set_defaults(func=command_verify_bundle)

    propose = sub.add_parser("propose-update", help="sign an add-operator proposal")
    propose.add_argument("bundle")
    propose.add_argument("--operator-set", default=str(DEFAULT_OPERATOR_SET))
    propose.add_argument("--signing-private-key-file", required=True)
    propose.add_argument("--signing-public-key", required=True)
    propose.add_argument("--allow-pending-burn-in", action="store_true")
    propose.add_argument("--created-at", type=int)
    propose.add_argument("--output")
    propose.set_defaults(func=command_propose_update)

    verify_update = sub.add_parser("verify-update", help="verify a signed operator-set update")
    verify_update.add_argument("update")
    verify_update.add_argument("--bundle", required=True)
    verify_update.add_argument("--operator-set", default=str(DEFAULT_OPERATOR_SET))
    verify_update.add_argument("--trusted-signing-key", action="append", required=True)
    verify_update.add_argument("--json", action="store_true")
    verify_update.set_defaults(func=command_verify_update)

    apply_update = sub.add_parser("apply-update", help="write the proposed operator set")
    apply_update.add_argument("update")
    apply_update.add_argument("--bundle", required=True)
    apply_update.add_argument("--operator-set", default=str(DEFAULT_OPERATOR_SET))
    apply_update.add_argument("--trusted-signing-key", action="append", required=True)
    apply_update.add_argument("--output")
    apply_update.add_argument("--in-place", action="store_true")
    apply_update.add_argument("--json", action="store_true")
    apply_update.set_defaults(func=command_apply_update)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except OperatorAdmissionError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
