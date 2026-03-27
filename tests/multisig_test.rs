use zorph_crypto::sign::{generate_keypair, sign};
use zorph_crypto::multisig::{create_multisig, verify_multisig};

#[test]
fn multisig_2_of_3() {
    let msg = b"multisig tx";
    let (sk1, pk1) = generate_keypair();
    let (sk2, pk2) = generate_keypair();
    let (_sk3, pk3) = generate_keypair();

    let sig1 = sign(&sk1, msg);
    let sig2 = sign(&sk2, msg);

    let sigs = vec![(pk1, sig1), (pk2, sig2)];
    assert!(verify_multisig(msg, &sigs, 2).is_ok());

    let bad_sigs = vec![(pk3, sign(&sk1, msg))];
    assert!(verify_multisig(msg, &bad_sigs, 1).is_err());
}

#[test]
fn create_and_verify_multisig() {
    let msg = b"approve transaction";
    let (sk1, _) = generate_keypair();
    let (sk2, _) = generate_keypair();
    let (sk3, _) = generate_keypair();

    let sigs = create_multisig(msg, &[&sk1, &sk2, &sk3]);
    assert_eq!(sigs.len(), 3);
    assert!(verify_multisig(msg, &sigs, 2).is_ok());
    assert!(verify_multisig(msg, &sigs, 3).is_ok());
}
