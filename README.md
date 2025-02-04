# Li₂utils
There is a significant lack of simple FIPS 204 (CRYSTALS-Dilithium) signature generators/verifiers.
This simple toolset is written in Rust and contains three tools: `li2sign`, `li2verify`, and `li2fingerprint`.

**This is provided for your convenience, and contains no audit, assurance, or fitness for any purpose whatsoever.**

This toolset relies completely on the great [`fips204`](https://crates.io/crates/fips204) Rust library by the RustCrypto Developers, and uses ML‐DSA‐44 parameters.

You can install the toolset from [Crates.io](https://crates.io/crates/li2utils) by issuing: `cargo install li2utils`

## li2sign
Usage: `li2sign`

Takes data from `stdin` and uses the private key from `./private_key.bin` if present; otherwise, it generates a new private key and stores it in that file. Then, it signs the given data, and outputs the signature to `stdout` and the public key to `stderr`.

## li2verify
Usage: `li2verify <public_key_hex> <signature_hex>`

Takes data from `stdin` and verifies it against `public_key_hex` and `signature_hex`. Outputs "`Signature is valid.`" to `stdin` or "`Signature is invalid.`" to `stderr`. On invalid signature, the program exits with `1`.

## li2fingerprint
Usage: `li2fingerprint <public_key_hex>`

Calculates SHAKE256 hash of the `public_key_hex` to provide 21-byte fingerprint in chunks of 3 bytes in hexadecimal (inspired by OpenPGP but with raw public key without the packet structure).

*Original author: Ville Sundell (with the help of generative AI), released in the public domain under CC0.*
