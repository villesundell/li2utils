use std::convert::TryInto;
use std::error::Error;
use std::fs;
use std::io::{self, Read};
use std::path::Path;

use fips204::ml_dsa_44;
use fips204::traits::{SerDes, Signer};

fn main() -> Result<(), Box<dyn Error>> {
    // 1. Read the data to be signed from standard input.
    let mut message = Vec::new();
    io::stdin().read_to_end(&mut message)?;

    // 2. Load or generate the private key.
    //    The private key is stored in "private_key.bin".
    let sk_path = "private_key.bin";
    let private_key = if Path::new(sk_path).exists() {
        // Read the private key bytes from the file.
        let sk_bytes = fs::read(sk_path)?;
        // Check that the file length is as expected (here, 2560 bytes).
        if sk_bytes.len() != 2560 {
            return Err("Invalid private key file length".into());
        }
        // Convert the Vec<u8> into a fixed-size array.
        let sk_array: [u8; 2560] = sk_bytes
            .try_into()
            .map_err(|_| "Failed to convert key bytes to fixed-size array")?;
        // Reconstruct the private key using the deserialization method provided by SerDes.
        <ml_dsa_44::PrivateKey as SerDes>::try_from_bytes(sk_array)?
    } else {
        // Generate a new key pair.
        let (_public_key, sk) = ml_dsa_44::try_keygen()?;
        // Save the private key bytes to the file.
        fs::write(sk_path, &<ml_dsa_44::PrivateKey as SerDes>::into_bytes(sk.clone()))?;
        sk
    };

    // Derive the public key from the private key.
    let public_key = private_key.get_public_key();

    // 3. Sign the input message.
    // (The empty slice is the NIST-specified context value.)
    let signature = private_key.try_sign(&message, &[])?;

    // 4. Output:
    //    - The public key (hex-encoded) is printed to standard error.
    //    - The signature (hex-encoded) is printed to standard output.
    eprintln!("Public Key (hex): {}", hex::encode(public_key.into_bytes()));
    println!("{}", hex::encode(signature));

    Ok(())
}
