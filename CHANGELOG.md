# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
