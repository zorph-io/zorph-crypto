use zorph_crypto::pqc::{
    generate_signing_keypair, hybrid_sign, hybrid_verify,
    generate_stateless_keypair, stateless_sign, stateless_verify,
};

fn main() {
    // hybrid Ed25519 + ML-DSA-65 — fast, quantum-safe
    let (sk, vk) = generate_signing_keypair();
    let message = b"document hash to sign";

    let sig = hybrid_sign(&sk, message).unwrap();
    println!("Hybrid signature: {} bytes", sig.to_bytes().len());

    hybrid_verify(&vk, message, &sig).unwrap();
    println!("Hybrid verification: OK");

    // SLH-DSA (SPHINCS+) — hash-based, maximum confidence
    let (slh_sk, slh_vk) = generate_stateless_keypair();
    let slh_sig = stateless_sign(&slh_sk, message).unwrap();
    println!("SLH-DSA signature: {} bytes (hash-based, conservative)", slh_sig.to_bytes().len());

    stateless_verify(&slh_vk, message, &slh_sig).unwrap();
    println!("SLH-DSA verification: OK");
}
