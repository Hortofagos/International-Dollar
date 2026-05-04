# International Dollar Wallet Auth And Recovery

Status: implementation in progress.

## Goal

International Dollar wallets should be low-friction for daily use while keeping
private keys encrypted at rest. Daily unlock should eventually be a 6-digit PIN
released by a hardware-backed keystore. The wallet password gates high-value
actions and can recover an existing device. A recovery phrase is the offline
fallback. Passkeys are optional.

## Master Wallet Key

Each wallet has one random 256-bit Master Wallet Key (MWK). The MWK encrypts
the wallet seed/private-key payload. The MWK is never stored in plaintext and
only lives in process memory while the wallet is unlocked.

The encrypted wallet file stores independent MWK wrappers. Any valid wrapper
can unwrap the same MWK:

- Password wrapper: Argon2id(wallet password, per-wallet salt), then AES-256-GCM
  over the MWK.
- Recovery phrase wrapper: Argon2id(recovery phrase, per-wallet salt), then
  AES-256-GCM over the MWK.
- Device wrapper: planned, hardware-keystore sealed key released after PIN.
- Passkey wrapper: planned, WebAuthn PRF output if the user opts in.

The current implemented wallet format is `INDW2`: AES-256-GCM payload
encryption, Argon2id password wrapper, optional recovery phrase wrapper, and
in-memory unlocked sessions.

## Daily Flow

Target flow:

1. App start prompts for a 6-digit PIN.
2. The OS hardware keystore verifies the PIN and releases a device-bound key.
3. The device key unwraps the MWK.
4. The wallet is ready.

The 6-digit PIN is acceptable only when the hardware keystore enforces attempt
limits and key destruction. The PIN must never be used as a standalone KDF
input.

Current flow:

1. App prompts for wallet password.
2. The password wrapper unwraps the MWK.
3. The wallet payload is decrypted in memory.

## Wallet Password Rules

- Minimum 10 characters.
- zxcvbn score at least 3 when the zxcvbn package is installed.
- Argon2id parameters: 256 MiB memory, 3 iterations, 4 lanes.
- Password changes should keep the old password wrapper valid for 30 days, with
  clear UI saying when the old password expires.

## Recovery Rules

- Forgot PIN, still have device: wallet password unwraps MWK and user sets a
  new PIN.
- Forgot password, still have device: PIN can keep daily use working, but
  setting a new password requires recovery phrase or delayed recovery.
- Lost device, has phrase and password: both should be required on a new device
  before rebinding to hardware keystore and setting a new PIN.
- Lost device, has phrase only: phrase unlock enters a 7-day delay before
  takeover.
- Lost device, lost phrase, lost password: unrecoverable.

The 7-day delay path needs trusted-state support from an existing device. A
copied wallet file plus phrase must not be enough to skip the delay.

## Hard Rules

- Never store seed or private key in plaintext.
- Never store password, PIN, or recovery phrase in plaintext, hashed, encrypted,
  partial, or as a hint.
- Never display password length or any character of any secret.
- Never derive the MWK from the PIN alone.
- Use Argon2id, not PBKDF2 or plain hashes, for new wallet wrappers.
- Use AES-256-GCM or XChaCha20-Poly1305 for symmetric encryption.
- Do not log secrets, including debug builds.

## Implementation Notes

- Legacy Fernet/PBKDF2 wallet files remain decryptable for migration.
- New wallet creation writes `INDW2` JSON files.
- New wallet generation stages the raw private key in process memory instead of
  writing `files/wallet_generation.json` with secrets.
- Unlocked wallets are held in process memory through `runtime_json` instead of
  being written as `wallet_decrypted_*` plaintext files.
- Existing plaintext decrypted wallet files are overwritten and removed when a
  wallet unlocks.
