use zorph_crypto::keys::{generate_recovery, from_recovery, derive_subkey};
use zorph_crypto::sharing::{split, reconstruct};

fn main() {
    // generate 24-word recovery phrase (BIP39-style)
    let words = generate_recovery();
    println!("Recovery phrase ({} words):", words.len());
    for (i, word) in words.iter().enumerate() {
        print!("{}. {}  ", i + 1, word);
        if (i + 1) % 6 == 0 { println!(); }
    }

    // recover the key from words
    let key = from_recovery(&words).unwrap();
    println!("Recovered key: {:02x?}", &key[..8]);

    // derive purpose-specific keys from the master
    let enc_key = derive_subkey(&key, "zorph file-encryption v1");
    let sign_key = derive_subkey(&key, "zorph signing v1");
    println!("Encryption key: {:02x?}", &enc_key[..8]);
    println!("Signing key:    {:02x?}", &sign_key[..8]);

    // Shamir split for team recovery (3-of-5)
    let shares = split(&key, 3, 5).unwrap();
    println!("\nShamir shares (3-of-5):");
    for share in &shares {
        println!("  Share {}: {} bytes", share.index, share.data.len());
    }

    // any 3 shares reconstruct the key
    let recovered = reconstruct(&shares[1..4], 3).unwrap();
    assert_eq!(recovered, key);
    println!("Reconstructed from shares 2,3,4: OK");
}
