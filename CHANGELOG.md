# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.3] - 2026-08-14

### Changed

- Upgrade `encryptman` from 0.2.2 to 0.3.0. Ciphertext format and keychain
  storage format are unchanged, so existing encrypted data and stored keys
  remain fully compatible — no migration needed.
- `MasterKey::generate()` is now fallible (encryptman 0.3.0 breaking
  change): `Vault::new()` / `Vault::new_with_target()` return
  `Error::Crypto` instead of panicking if the OS random number generator
  is unavailable.
- Key material read during `migrate_from_file()` is now zeroized on all
  code paths before being dropped, matching encryptman 0.3.0's memory
  hygiene guarantees.

### Security

- Added `#![forbid(unsafe_code)]` — the crate guarantees it contains no
  unsafe code.

## [0.1.2] - 2026-08-06

### Changed

- Update dependency versions (encryptman 0.2.2, keyring 4.1.6, thiserror 2.0.19)

## [0.1.1] - 2026-07-23

### Changed

- Rename `.tb_key` to `.key` to remove tb-plus references
- Update documentation and examples
- Apply rustfmt formatting

## [0.1.0] - 2026-07-22

### Added

- `Vault` struct — encrypt/decrypt with automatic OS keychain key management
- `Vault::new()` — create or load vault with default target
- `Vault::new_with_target()` — create or load vault with custom keyring username
- `Vault::encrypt()` / `Vault::decrypt()` — delegate to `encryptman`
- `Vault::encrypt_with_context()` / `Vault::decrypt_with_context()` — context-isolated encryption
- `Vault::encrypt_bytes()` / `Vault::decrypt_bytes()` — binary data encryption
- `Vault::encrypt_bytes_with_context()` / `Vault::decrypt_bytes_with_context()` — binary data with custom HKDF context
- `Vault::master_key()` — direct access to underlying `MasterKey`
- `Vault::delete()` / `Vault::delete_with_target()` — associated functions to remove key from OS keychain
- `Vault::migrate_from_file()` — import existing file-based key and delete file
- `Vault::migrate_from_file_with_target()` — migrate with custom target
- `Error` enum with `Keychain`, `InvalidKeyLength`, `FileRead`, `InvalidFileKeyLength`, `Crypto` variants
- Comprehensive test suite (13 tests)
