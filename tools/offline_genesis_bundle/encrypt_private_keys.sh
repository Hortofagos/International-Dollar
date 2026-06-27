#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

secure_delete() {
  local path="$1"
  if [[ -f "$path" ]]; then
    if command -v shred >/dev/null 2>&1; then
      shred -u "$path" || rm -f "$path"
    else
      rm -f "$path"
    fi
  fi
}

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
KEYS_DIR="$SCRIPT_DIR/keys"
BACKUP_DIR="${1:-$SCRIPT_DIR/private-backups}"

require_command date
require_command gpg
require_command mkdir
require_command sha256sum
require_command tar

[[ -d "$KEYS_DIR" ]] || fail "keys directory not found: $KEYS_DIR"

if command -v tty >/dev/null 2>&1 && tty -s; then
  export GPG_TTY="$(tty)"
fi

chmod 700 "$KEYS_DIR"
find "$KEYS_DIR" -maxdepth 1 -type f -name '*_private.local.txt' -exec chmod 600 {} +

shopt -s nullglob
private_paths=("$KEYS_DIR"/*_private.local.txt)
shopt -u nullglob

((${#private_paths[@]} > 0)) || fail "no private key files found in $KEYS_DIR"

mapfile -t private_names < <(printf '%s\n' "${private_paths[@]##*/}" | sort)

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

timestamp="$(date -u +%Y%m%d-%H%M%S)"
backup_name="ind-mainnet-genesis-private-keys-${timestamp}.tar.gpg"
encrypted_backup="$BACKUP_DIR/$backup_name"
checksum_file="$encrypted_backup.sha256"
tmp_tar="$(mktemp "${TMPDIR:-/tmp}/ind-mainnet-genesis-private-keys.XXXXXX.tar")"
listing_file="$(mktemp "${TMPDIR:-/tmp}/ind-mainnet-genesis-private-keys.XXXXXX.list")"

cleanup() {
  secure_delete "$tmp_tar"
  rm -f "$listing_file"
}
trap cleanup EXIT

[[ ! -e "$encrypted_backup" ]] || fail "backup already exists: $encrypted_backup"

printf 'Packing private key files from %s\n' "$KEYS_DIR"
tar -C "$KEYS_DIR" -cf "$tmp_tar" "${private_names[@]}"

printf 'Encrypting backup with gpg AES256. Choose a long passphrase.\n'
gpg --symmetric --cipher-algo AES256 --output "$encrypted_backup" "$tmp_tar"

(cd "$BACKUP_DIR" && sha256sum "$backup_name" > "$(basename "$checksum_file")")
chmod 600 "$encrypted_backup" "$checksum_file"

printf 'Verifying encrypted backup. gpg may ask for the passphrase again.\n'
if ! gpg --quiet --decrypt "$encrypted_backup" | tar -tf - > "$listing_file"; then
  rm -f "$encrypted_backup" "$checksum_file"
  fail "encrypted backup verification failed; deleted incomplete output"
fi

printf '\nEncrypted backup created:\n'
printf '  %s\n' "$encrypted_backup"
printf 'Checksum:\n'
printf '  %s\n' "$checksum_file"
printf '\nEncrypted contents:\n'
sed 's/^/  /' "$listing_file"
printf '\nKeep plaintext private keys on the offline machine only:\n'
printf '  %s/*_private.local.txt\n' "$KEYS_DIR"
