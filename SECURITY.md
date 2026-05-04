# Security Policy

IND is experimental alpha software. Do not use it for real funds or irreversible commerce until the protocol and implementation have been independently reviewed.

## Reporting

Please report security issues privately before publishing details. If no dedicated project security email is available yet, open a GitHub issue requesting a private disclosure channel and include no exploit details in the public issue.

Helpful reports include:

- affected version or commit
- steps to reproduce
- expected impact
- proof-of-concept data, if safe to share privately

## Sensitive Files

Never commit runtime secrets or local state, including:

- wallet files
- RSA private keys
- passphrases
- local databases
- public IP cache
- transaction scratch files

Any key that was previously committed or shared should be treated as compromised and regenerated.

## Supported Versions

Only the current `main` branch is in scope during alpha.
