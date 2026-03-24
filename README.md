# frankshoard

A secure, offline password vault written in Rust.

---

## About

`frankshoard` is a local password manager built as a hands-on Rust learning project, with a deliberate focus on getting the security design right from the ground up. Rather than relying on external frameworks for the security-critical components, the vault is designed with well-understood, modern cryptographic primitives chosen for their security properties.

The name is a portmanteau of *Frank* (the author) and *hoard* — a personal stash of secrets, kept offline and under your control.

---

## Building

This has only been test on MacOS Sequoia so far. 

```bash
git clone https://github.com/Sickghost/frankshoard
cd frankshoard
cargo build
```

Requires Rust stable (1.70+).

---

## Usage

Assuming the binary is in your path, invoke help on it.

```bash
frankshoard --help
```

Note that by default it will look for a config file in `~/.config/frankshoard`.  You can provide a path to the config file via the cli.
If no configuration file are present, a default one is created.  The default setting uses just under 2 GiB (1953000 KiB) of memory to derive the key.  Even on a good computer this can take quite some time so you may want to change the default to something more reasonable.

See `config/config.example.toml` to create and customize your own.

## Security Design

Security decisions are documented here:

**Key Derivation**
- Master password is never stored directly
- Keys are derived using **Argon2id** 
- Argon2id is preferred over PBKDF2 or bcrypt due to its memory-hardness, which significantly raises the cost of GPU-based brute-force attacks

**Vault Encryption**
- Vault contents are encrypted using **AES-256-GCM** (Authenticated Encryption with Associated Data)
- AES-GCM provides both confidentiality and integrity — any tampering with the ciphertext is detectable
- A unique nonce is generated per encryption operation

**Secrecy Crate**
- The secrecy crate is not used by choice.  I may refactor that later.

---

## Architecture

The project is structured around the following modules:

- **config** — handles application configuration, paths, and user preferences
- **vault** — core vault storage, entry management, and serialization 
- **crypto** — cryptographic primitives: Argon2id key derivation and AES-GCM encryption/decryption 
- **lib** — the public api
- **cli** — command-line interface for interacting with the vault *(planned)*

---

## Motivation

This project serves two purposes:

1. **Learning Rust** — particularly ownership, borrowing, error handling, and working with low-level cryptographic libraries in a safe systems language
2. **Applying security engineering principles** — designing a system where security is a foundational constraint, not an afterthought

The combination of Rust's memory safety guarantees and carefully chosen cryptographic primitives makes this a practical exercise in building software that is both correct and secure.

---

## Roadmap

- [x] Project structure and configuration layer
- [x] Vault storage and entry management
- [x] Argon2id key derivation
- [x] AES-256-GCM encryption/decryption
- [x] Public API layer (Master password change with vault re-encryption, list, add, delete, edit)
- [x] CLI interface

Release 1

- [ ] Add "verbose mode" and remove all none-essential printouts from none verbose mode
- [ ] Test Suite
- [ ] Add a GUI
- [ ] Add Interractive session to cli
- [ ] Add a threaded timer to manage master_key lifecycle.

---


## License

BSD-3-Clause
