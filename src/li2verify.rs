use std::env;
use std::error::Error;
use std::io::{self, Read};
use std::convert::TryInto;

use fips204::ml_dsa_44;
use fips204::traits::{SerDes, Verifier};

fn main() -> Result<(), Box<dyn Error>> {
    // Expect two command-line arguments: public key and signature (hex encoded).
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: li2verify <public_key_hex> <signature_hex>");
        std::process::exit(1);
    }
    
    let public_key_hex = &args[1];
    let signature_hex = &args[2];
    
    // Decode the hex strings into bytes.
    let pk_bytes = hex::decode(public_key_hex)?;
    let sig_bytes = hex::decode(signature_hex)?;
    
    // --- Reconstruct the Public Key ---
    // Adjust the expected length to match your parameter set.
    const PK_LENGTH: usize = 1312;  // Change this to your actual public key byte length.
    if pk_bytes.len() != PK_LENGTH {
        return Err(format!(
            "Invalid public key length: expected {} bytes, got {}",
            PK_LENGTH,
            pk_bytes.len()
        ).into());
    }
    let pk_array: [u8; PK_LENGTH] = pk_bytes
        .try_into()
        .map_err(|_| "Failed to convert public key bytes to fixed-size array")?;
    
    // Use the SerDes trait to deserialize the public key.
    let public_key = <ml_dsa_44::PublicKey as SerDes>::try_from_bytes(pk_array)?;
    
    // --- Reconstruct the Signature ---
    // Adjust the expected length to match your parameter set.
    const SIG_LENGTH: usize = 2420;  // Change this to your actual signature byte length.
    if sig_bytes.len() != SIG_LENGTH {
        return Err(format!(
            "Invalid signature length: expected {} bytes, got {}",
            SIG_LENGTH,
            sig_bytes.len()
        ).into());
    }
    let sig_array: [u8; SIG_LENGTH] = sig_bytes
        .try_into()
        .map_err(|_| "Failed to convert signature bytes to fixed-size array")?;
    
    // In our parameter set the signature type is a fixed-size array.
    let signature = sig_array;
    
    // --- Read the Message from Standard Input ---
    let mut message = Vec::new();
    io::stdin().read_to_end(&mut message)?;
    
    // --- Verify the Signature ---
    // The empty slice is the context (typically unused).
    let valid = public_key.verify(&message, &signature, &[]);
    
    if valid {
        println!("Signature is valid.");
        Ok(())
    } else {
        eprintln!("Signature is invalid.");
        std::process::exit(1);
    }
}
