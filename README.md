# Li₂utils
There is a significant lack of simple FIPS 204 (CRYSTALS-Dilithium) signature generators/verifiers.
This simple toolset is written in Rust and contains two tools: `li2sign` and `li2verify`.

**This is provided for your convenience, and contains no audit, assurance, or fitness for any purpose whatsoever.**

This toolset relies completely on the great [`fips204`](https://crates.io/crates/fips204) Rust library by the RustCrypto Developers, and uses ML‐DSA‐44 parameters.

## li2sign
Usage: `li2sign`

Takes data from `stdin` and uses the private key from `./private_key.bin` if present; otherwise, it generates a new private key and stores it in that file. Then, it signs the given data, and outputs the signature to `stdout` and the public key to `stderr`.

## li2verify
Usage: `li2verify <public_key_hex> <signature_hex>`

Takes data from `stdin` and verifies it against `public_key_hex` and `signature_hex`.

*Original author: Ville Sundell (with the help of generative AI), released in the public domain under CC0.*
