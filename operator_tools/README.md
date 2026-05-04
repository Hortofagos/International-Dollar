# IND Transparency Operator Tools

This folder contains operator-side helpers for mirroring signed transparency
roots outside the proof-serving log operator.

`root_streamer.py` copies signed Merkle roots into:

- a git mirror directory, with optional commits/pushes
- a static website directory that clients can read as a root mirror

It mirrors signed roots only. It does not mirror full transfer payloads, and it
does not need the full transfer-hash SQLite log.

`hash_log_exporter.py` is the heavier auditor path. It exports the full
append-only log of transfer hashes into static JSONL segment files. This is
useful for monitors that want to recompute roots independently, but it should
live in object storage, IPFS, archive snapshots, or a static file host rather
than an ordinary git repo.

## Placeholder Run

Start the log operator with a local staging mirror:

```bash
python log_server.py --host 127.0.0.1 --port 8890 --mirror-dir files/transparency_roots
```

Stream roots once from the running operator into placeholder git and website
directories:

```bash
python -m operator_tools.root_streamer --once
```

Real deployment should replace the placeholders:

```bash
python -m operator_tools.root_streamer `
  --operator-url http://127.0.0.1:8890 `
  --operator-public-key "<operator-public-key>" `
  --git-mirror-dir C:\path\to\transparency-roots-clone `
  --git-remote-url https://example.invalid/ind/transparency-roots.git `
  --website-mirror-dir C:\path\to\website\public\transparency `
  --git-push
```

For a daemon-like loop, omit `--once`. The default polling interval is 60
seconds.

Export full hash-log pages for auditors:

```bash
python -m operator_tools.hash_log_exporter `
  --operator-url http://127.0.0.1:8890 `
  --archive-dir C:\path\to\large\hash-log-archive `
  --once
```

## Published Files

Each mirror contains:

- `roots/root_<timestamp>_<tree_size>_<root_hash_prefix>.json`
- `roots.jsonl`
- `latest.json`
- `manifest.json`

Clients can point `IND_LOG_MIRROR_URLS` at the static website directory or at a
published HTTP equivalent.

Hash-log archive files are separate:

- `entries/entries_<first>_<last>.jsonl`
- `manifest.json`

Each entry is only `{leaf_index, entry_hash, submitted_at}`. Full transfer data
still stays peer-to-peer.
