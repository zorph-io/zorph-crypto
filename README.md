# zorph-crypto

Cryptographic primitives for the [Zorph](https://zorph.io) platform. MIT-licensed, zero unsafe code.

Built on audited RustCrypto crates + NIST post-quantum standards (FIPS 203/204/205).

## Modules

| Module | What it does |
|--------|-------------|
| `encrypt` | AES-256-GCM, ChaCha20-Poly1305, streaming, envelope encryption (DEK/KEK), versioned format |
| `keys` | Argon2id key derivation (configurable), BIP39 recovery phrases, BLAKE3 subkey derivation |
| `sign` | Ed25519 signatures with key serialization |
| `hash` | BLAKE3 hashing, streaming hasher, keyed MAC |
| `exchange` | X25519 Diffie-Hellman with BLAKE3 KDF |
| `multisig` | N-of-M threshold signatures with deduplication |
| `sharing` | Shamir secret sharing (binary-safe) |
| `pqc` | Hybrid Ed25519+ML-DSA-65 signing, X25519+ML-KEM-768 key exchange, SLH-DSA backup |
| `attest` | AMD SEV-SNP attestation verification, X.509 cert chain (ARK -> ASK -> VCEK) |
| `zk` | Commitments, Merkle trees, signed proof envelopes |
| `wipe` | Zeroize wrappers, SecureBuffer |

## Install

```toml
[dependencies]
zorph-crypto = { git = "https://github.com/zorph-io/zorph-crypto" }
```

## Quick start

### Encrypt / Decrypt

```rust
use zorph_crypto::encrypt::{seal, open, Cipher};

let key = [0x42u8; 32];
let ciphertext = seal(&key, b"secret data", Cipher::Aes256Gcm).unwrap();
let plaintext = open(&key, &ciphertext).unwrap();
```

### Envelope encryption (DEK/KEK)

```rust
use zorph_crypto::encrypt::{envelope_seal, envelope_open, Cipher};

let master_key = [0x42u8; 32];
let encrypted = envelope_seal(&master_key, b"file contents", Cipher::Aes256Gcm).unwrap();
let decrypted = envelope_open(&master_key, &encrypted).unwrap();
```

### Key derivation

```rust
use zorph_crypto::keys::{derive_key, derive_key_with_params, Argon2Params};

// server-side (64MB, 3 iterations)
let key = derive_key(b"password", b"random-salt!").unwrap();

// mobile/CLI (19MB, 2 iterations)
let key = derive_key_with_params(b"password", b"random-salt!", Argon2Params::INTERACTIVE).unwrap();
```

### Recovery phrase

```rust
use zorph_crypto::keys::{generate_recovery, from_recovery};

let words = generate_recovery(); // 24 BIP39 words
let key = from_recovery(&words).unwrap(); // -> [u8; 32]
```

### Sign / Verify

```rust
use zorph_crypto::sign::{generate_keypair, sign, verify};

let (secret, public) = generate_keypair();
let sig = sign(&secret, b"document hash");
assert!(verify(&public, b"document hash", &sig).is_ok());
```

### Post-quantum hybrid signatures

```rust
use zorph_crypto::pqc::{generate_signing_keypair, hybrid_sign, hybrid_verify};

let (sk, vk) = generate_signing_keypair();
let sig = hybrid_sign(&sk, b"quantum-safe message").unwrap();
assert!(hybrid_verify(&vk, b"quantum-safe message", &sig).is_ok());
```

### Streaming hash (large files)

```rust
use zorph_crypto::hash::Hasher;

let mut hasher = Hasher::new();
hasher.update(b"chunk 1");
hasher.update(b"chunk 2");
let hash = hasher.finalize(); // [u8; 32]
```

### Shamir secret sharing

```rust
use zorph_crypto::sharing::{split, reconstruct};

let shares = split(b"master-key-bytes-here!", 3, 5).unwrap(); // 3-of-5
let recovered = reconstruct(&shares[..3], 3).unwrap();
```

## Examples

```bash
cargo run --example encrypt_file
cargo run --example derive_key
cargo run --example hybrid_sign
cargo run --example envelope
cargo run --example streaming
cargo run --example recovery
```

## Security

- All crypto from audited RustCrypto crates — no custom implementations
- Constant-time comparisons where needed (subtle crate)
- Keys zeroized on drop (zeroize crate)
- Post-quantum hybrid mode: both classical and PQC must be broken simultaneously
- AMD SEV-SNP attestation for enclave verification

## License

MIT
