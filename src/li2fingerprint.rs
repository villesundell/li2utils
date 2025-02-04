use std::env;
use std::error::Error;

use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};
use hex;

fn main() -> Result<(), Box<dyn Error>> {
    // Expect exactly one argument: the public key in hex.
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: li2fingerprint <public_key_hex>");
        std::process::exit(1);
    }
    let pubkey_hex = &args[1];

    // Decode the public key from hex into raw bytes.
    let pubkey_bytes = hex::decode(pubkey_hex)
        .map_err(|e| format!("Failed to decode hex public key: {}", e))?;

    // Use SHAKE256 (an extendable output function from SHA-3) to produce a 21-byte output.
    let mut hasher = Shake256::default();
    hasher.update(&pubkey_bytes);
    let mut xof = hasher.finalize_xof();
    let mut fingerprint = [0u8; 21];
    xof.read(&mut fingerprint);
    
    // Optionally, format the fingerprint into groups for readability.
    let raw_fp = hex::encode_upper(fingerprint);
    println!("{}", format_fingerprint(&raw_fp));
    
    Ok(())
}

/// Format a hex string by grouping every 4 bytes (optional).
fn format_fingerprint(fp: &str) -> String {
    fp
        .chars()
        .collect::<Vec<_>>()
        .chunks(6)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect::<Vec<String>>()
        .join(" ")
}
