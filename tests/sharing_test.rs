use zorph_crypto::sharing::{split, reconstruct};

#[test]
fn split_reconstruct_text() {
    let secret = b"my secret password";
    let shares = split(secret, 3, 5).unwrap();
    assert_eq!(shares.len(), 5);

    let recovered = reconstruct(&shares[..3], 3).unwrap();
    assert_eq!(recovered, secret);
}

#[test]
fn split_reconstruct_binary() {
    // raw 32-byte key — no valid UTF-8
    let secret: Vec<u8> = (0..32).collect();
    let shares = split(&secret, 2, 3).unwrap();

    let recovered = reconstruct(&shares[..2], 2).unwrap();
    assert_eq!(recovered, secret);
}

#[test]
fn split_reconstruct_all_byte_values() {
    // every possible byte value
    let secret: Vec<u8> = (0u8..=255).collect();
    let shares = split(&secret, 2, 3).unwrap();

    let recovered = reconstruct(&shares[..2], 2).unwrap();
    assert_eq!(recovered, secret);
}

#[test]
fn different_share_subsets_recover_same_secret() {
    let secret = b"shared secret";
    let shares = split(secret, 2, 4).unwrap();

    let r1 = reconstruct(&[shares[0].clone(), shares[1].clone()], 2).unwrap();
    let r2 = reconstruct(&[shares[2].clone(), shares[3].clone()], 2).unwrap();
    let r3 = reconstruct(&[shares[0].clone(), shares[3].clone()], 2).unwrap();

    assert_eq!(r1, secret);
    assert_eq!(r2, secret);
    assert_eq!(r3, secret);
}

#[test]
fn insufficient_shares_fails() {
    let secret = b"need three";
    let shares = split(secret, 3, 5).unwrap();

    // only 2 shares, threshold is 3
    let result = reconstruct(&shares[..2], 3);
    assert!(result.is_err());
}

#[test]
fn empty_secret_fails() {
    assert!(split(b"", 2, 3).is_err());
}

#[test]
fn threshold_less_than_2_fails() {
    assert!(split(b"secret", 1, 3).is_err());
}

#[test]
fn total_less_than_threshold_fails() {
    assert!(split(b"secret", 5, 3).is_err());
}

#[test]
fn split_reconstruct_32byte_key() {
    let secret = [0xABu8; 32];
    let shares = split(&secret, 3, 5).unwrap();
    let recovered = reconstruct(&shares[1..4], 3).unwrap();
    assert_eq!(recovered, secret);
}
