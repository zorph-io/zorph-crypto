use criterion::{black_box, criterion_group, criterion_main, Criterion};
use zorph_crypto::{encrypt, hash, keys, pqc, sign, exchange};

fn bench_encrypt(c: &mut Criterion) {
    let key = [0x42u8; 32];
    let data = vec![0u8; 1024];
    c.bench_function("aes256gcm_encrypt_1kb", |b| {
        b.iter(|| encrypt::encrypt(black_box(&key), black_box(&data)).unwrap())
    });
}

fn bench_chacha20_encrypt(c: &mut Criterion) {
    let key = [0x42u8; 32];
    let data = vec![0u8; 1024];
    c.bench_function("chacha20poly1305_seal_1kb", |b| {
        b.iter(|| {
            encrypt::seal(
                black_box(&key),
                black_box(&data),
                encrypt::Cipher::ChaCha20Poly1305,
            )
            .unwrap()
        })
    });
}

fn bench_hash(c: &mut Criterion) {
    let data = vec![0u8; 1024];
    c.bench_function("blake3_hash_1kb", |b| {
        b.iter(|| hash::hash(black_box(&data)))
    });
}

fn bench_derive_key(c: &mut Criterion) {
    c.bench_function("argon2id_derive_key", |b| {
        b.iter(|| keys::derive_key(black_box(b"password"), black_box(b"saltsalt")).unwrap())
    });
}

fn bench_ed25519_sign(c: &mut Criterion) {
    let (sk, _vk) = sign::generate_keypair();
    let msg = vec![0u8; 256];
    c.bench_function("ed25519_sign_256b", |b| {
        b.iter(|| sign::sign(black_box(&sk), black_box(&msg)))
    });
}

fn bench_ed25519_verify(c: &mut Criterion) {
    let (sk, vk) = sign::generate_keypair();
    let msg = vec![0u8; 256];
    let sig = sign::sign(&sk, &msg);
    c.bench_function("ed25519_verify_256b", |b| {
        b.iter(|| sign::verify(black_box(&vk), black_box(&msg), black_box(&sig)).unwrap())
    });
}

fn bench_x25519_exchange(c: &mut Criterion) {
    c.bench_function("x25519_key_exchange", |b| {
        b.iter(|| {
            let (secret_a, _pub_a) = exchange::generate_keypair();
            let (_secret_b, pub_b) = exchange::generate_keypair();
            exchange::diffie_hellman(secret_a, &pub_b)
        })
    });
}

fn bench_hybrid_keygen(c: &mut Criterion) {
    c.bench_function("hybrid_signing_keygen", |b| {
        b.iter(|| pqc::generate_signing_keypair())
    });
}

fn bench_hybrid_sign(c: &mut Criterion) {
    let (sk, _vk) = pqc::generate_signing_keypair();
    let msg = vec![0u8; 256];
    c.bench_function("hybrid_sign_256b", |b| {
        b.iter(|| pqc::hybrid_sign(black_box(&sk), black_box(&msg)).unwrap())
    });
}

fn bench_hybrid_verify(c: &mut Criterion) {
    let (sk, vk) = pqc::generate_signing_keypair();
    let msg = vec![0u8; 256];
    let sig = pqc::hybrid_sign(&sk, &msg).unwrap();
    c.bench_function("hybrid_verify_256b", |b| {
        b.iter(|| pqc::hybrid_verify(black_box(&vk), black_box(&msg), black_box(&sig)).unwrap())
    });
}

fn bench_hybrid_exchange(c: &mut Criterion) {
    c.bench_function("hybrid_key_exchange", |b| {
        b.iter(|| {
            let kp = pqc::generate_exchange_keypair();
            let (msg, _secret) = pqc::hybrid_exchange_initiate(&kp.x25519_public, &kp.mlkem_ek);
            pqc::hybrid_exchange_respond(&msg, kp.x25519_secret, &kp.mlkem_dk)
        })
    });
}

fn bench_slh_dsa_sign(c: &mut Criterion) {
    let (sk, _vk) = pqc::generate_stateless_keypair();
    let msg = vec![0u8; 256];
    c.bench_function("slh_dsa_sign_256b", |b| {
        b.iter(|| pqc::stateless_sign(black_box(&sk), black_box(&msg)).unwrap())
    });
}

fn bench_slh_dsa_verify(c: &mut Criterion) {
    let (sk, vk) = pqc::generate_stateless_keypair();
    let msg = vec![0u8; 256];
    let sig = pqc::stateless_sign(&sk, &msg).unwrap();
    c.bench_function("slh_dsa_verify_256b", |b| {
        b.iter(|| pqc::stateless_verify(black_box(&vk), black_box(&msg), black_box(&sig)).unwrap())
    });
}

criterion_group!(
    benches,
    bench_encrypt,
    bench_chacha20_encrypt,
    bench_hash,
    bench_derive_key,
    bench_ed25519_sign,
    bench_ed25519_verify,
    bench_x25519_exchange,
    bench_hybrid_keygen,
    bench_hybrid_sign,
    bench_hybrid_verify,
    bench_hybrid_exchange,
    bench_slh_dsa_sign,
    bench_slh_dsa_verify,
);
criterion_main!(benches);
