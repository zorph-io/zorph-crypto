use zorph_crypto::encrypt::{StreamSealer, StreamOpener, Cipher};
use zorph_crypto::hash::Hasher;

fn main() {
    let key = [0x42u8; 32];

    // streaming encryption — process data chunk by chunk without loading everything into memory
    let chunks: Vec<&[u8]> = vec![
        b"header: financial report\n",
        b"section 1: revenue $12M\n",
        b"section 2: expenses $8M\n",
        b"footer: confidential\n",
    ];

    let (mut sealer, header) = StreamSealer::new(&key, Cipher::Aes256Gcm);
    println!("Stream header: {} bytes (tag + nonce prefix)", header.len());

    let encrypted_chunks: Vec<Vec<u8>> = chunks
        .iter()
        .map(|chunk| sealer.seal_chunk(chunk).unwrap())
        .collect();

    println!("Encrypted {} chunks", encrypted_chunks.len());

    // decrypt in the same order
    let mut opener = StreamOpener::new(&key, &header).unwrap();
    for (i, ct) in encrypted_chunks.iter().enumerate() {
        let pt = opener.open_chunk(ct).unwrap();
        println!("Chunk {}: {}", i, String::from_utf8_lossy(&pt).trim());
    }

    // streaming hash — same pattern for large files
    let mut hasher = Hasher::new();
    for chunk in &chunks {
        hasher.update(chunk);
    }
    println!("File hash: {}", hasher.finalize_hex());
}
