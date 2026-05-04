# Local Genesis Workspace

This folder is for local genesis generation output. Generated shards, manifests, issuer keys, and hash files are ignored by git.

Use `tools/generate_genesis.py` to create small test sets or a launch commitment. Do not commit generated private keys or full genesis shards.

For a real public launch, publish only the agreed public artifacts: issuer public key policy, manifest, test vectors, and the final genesis commitment.
