use zorph_crypto::keys;

#[test]
fn hash_and_verify_password() {
    let password = b"correct horse battery staple";
    let hash = keys::hash_password(password).unwrap();

    // PHC format starts with $argon2id$
    assert!(hash.starts_with("$argon2id$"));

    // correct password verifies
    assert!(keys::verify_password(password, &hash).unwrap());

    // wrong password fails
    assert!(!keys::verify_password(b"wrong", &hash).unwrap());
}

#[test]
fn hash_password_unique_salts() {
    let password = b"same password";
    let h1 = keys::hash_password(password).unwrap();
    let h2 = keys::hash_password(password).unwrap();
    // different salts → different hashes
    assert_ne!(h1, h2);
    // but both verify
    assert!(keys::verify_password(password, &h1).unwrap());
    assert!(keys::verify_password(password, &h2).unwrap());
}

#[test]
fn hash_password_with_interactive_params() {
    let password = b"interactive";
    let hash =
        keys::hash_password_with_params(password, keys::Argon2Params::INTERACTIVE).unwrap();
    assert!(keys::verify_password(password, &hash).unwrap());
}

#[test]
fn verify_password_invalid_hash_format() {
    let result = keys::verify_password(b"pass", "not-a-valid-hash");
    assert!(result.is_err());
}
