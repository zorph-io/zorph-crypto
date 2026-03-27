use zorph_crypto::keys::SecretKey;

fn main() {
    let sk = SecretKey::from_password(b"my-password", b"random-salt!")
        .expect("key derivation failed");
    println!("Derived key: {} bytes", sk.as_bytes().len());
    println!("Key (hex): {:02x?}", sk.as_bytes());
}
