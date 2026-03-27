use zorph_crypto::keys::{derive_key, derive_key_with_params, derive_subkey, Argon2Params, SecretKey};

fn main() {
    // server preset (64MB, 3 iterations, 4 threads)
    let key = derive_key(b"my-password", b"random-salt!").unwrap();
    println!("Server key: {:02x?}", &key[..8]);

    // interactive preset (19MB, lighter — good for CLI/mobile)
    let key2 = derive_key_with_params(b"my-password", b"random-salt!", Argon2Params::INTERACTIVE).unwrap();
    println!("Interactive key: {:02x?}", &key2[..8]);

    // SecretKey wrapper (zeroized on drop)
    let sk = SecretKey::from_password(b"my-password", b"random-salt!").unwrap();
    println!("SecretKey: {} bytes", sk.as_bytes().len());

    // subkey derivation with domain separation
    let enc_key = derive_subkey(sk.as_bytes(), "zorph file-encryption v1");
    let mac_key = derive_subkey(sk.as_bytes(), "zorph file-mac v1");
    println!("Encryption subkey: {:02x?}", &enc_key[..8]);
    println!("MAC subkey:        {:02x?}", &mac_key[..8]);
    assert_ne!(enc_key, mac_key);
}
