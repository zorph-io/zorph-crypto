# zorph-crypto

Cryptographic primitives for the Zorph platform.

## Features

- **AES-256-GCM** — authenticated encryption
- **Argon2id** — password-based key derivation
- **Ed25519** — digital signatures
- **BLAKE3** — fast cryptographic hashing
- **X25519** — Diffie-Hellman key exchange
- **Shamir Secret Sharing** — key recovery
- **Multisig** — N-of-M signature verification
- **SEV-SNP** — attestation verification
- **Post-quantum** — placeholder for Phase 2

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
zorph-crypto = { git = "https://github.com/nickolaev-dev/zorph-crypto" }
```

### Encrypt / Decrypt

```rust
use zorph_crypto::encrypt::{encrypt, decrypt};

let key = [0u8; 32];
let plaintext = b"hello world";
let ciphertext = encrypt(&key, plaintext).unwrap();
let decrypted = decrypt(&key, &ciphertext).unwrap();
assert_eq!(decrypted, plaintext);
```

### Derive Key

```rust
use zorph_crypto::keys::derive_key;

let key = derive_key(b"password", b"salt").unwrap();
```

### Sign / Verify

```rust
use zorph_crypto::sign::{generate_keypair, sign, verify};

let (secret, public) = generate_keypair();
let message = b"hello";
let signature = sign(&secret, message);
assert!(verify(&public, message, &signature).is_ok());
```

## License

MIT
