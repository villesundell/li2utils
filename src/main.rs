use fips204::ml_dsa_44; // Alternatively, you can use ml_dsa_65 or ml_dsa_87.
use fips204::traits::{SerDes, Signer, Verifier};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A sample message to be signed.
    let message = [0u8, 1, 2, 3, 4, 5, 6, 7];

    // --- Key Generation and Signing ---
    // Generate a key pair: public key `pk1` and secret key `sk`.
    let (pk1, sk) = ml_dsa_44::try_keygen()?;
    // Sign the message with the secret key.
    let sig = sk.try_sign(&message, &[])?;

    // --- Serialization (Simulated Transmission) ---
    // Convert the public key to bytes for sending.
    let pk_send = pk1.into_bytes();
    // In a real application, you would now send `pk_send`, `message`, and `sig` to a receiver.
    // Here we simply reassign them to simulate reception.
    let (pk_recv, msg_recv, sig_recv) = (pk_send, message, sig);

    // --- Deserialization and Verification ---
    // Convert the received bytes back into a public key.
    let pk2 = ml_dsa_44::PublicKey::try_from_bytes(pk_recv)?;
    // Verify the received message and signature.
    let is_valid = pk2.verify(&msg_recv, &sig_recv, &[]);
    assert!(is_valid, "Signature verification failed!");

    println!("Signature verified successfully!");
    Ok(())
}
