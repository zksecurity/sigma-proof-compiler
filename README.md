# Sigma Proof Compiler

A Rust library for creating and verifying sigma protocols (zero-knowledge proofs of knowledge) using symbolic computation over elliptic curves.

## ⚠️ Experimental Warning

**This library is experimental and not production-ready.** It is intended for research, prototyping, and educational purposes only. Do not use this library in production systems or for securing real assets. The implementation has not undergone security audits and may contain bugs or vulnerabilities.

## Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
sigma-proof-compiler = "0.1.0"
```

## Example: Schnorr Identity Protocol

Here's a complete example implementing a Schnorr identity protocol that proves knowledge of a discrete logarithm:

```rust
use sigma_proof_compiler::{
    absorb::{SymInstance, SymWitness},
    compiler::SigmaProof,
    equations::{SymPoint, SymScalar},
};
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, Scalar};

// Define the protocol
pub struct SchnorrIdentityProtocol;

// The secret witness (what the prover knows)
#[derive(SymWitness, Clone)]
pub struct SchnorrWitness {
    privatekey: SymScalar,
}

// The public instance (what everyone can see)
#[derive(SymInstance, Clone)]
pub struct SchnorrInstance {
    pubkey: SymPoint,
}

impl SigmaProof for SchnorrIdentityProtocol {
    const LABEL: &'static [u8] = b"schnorr-identity-protocol";

    type WITNESS = SchnorrWitness;
    type INSTANCE = SchnorrInstance;

    // Instance function: public key (= private_key * G)
    fn f(instance: &Self::INSTANCE) -> Vec<SymPoint> {
        vec![instance.pubkey.clone()]
    }

    // Witness function: commitment = private_key * G (using symbolic arithmetic)
    fn psi(witness: &Self::WITNESS, _instance: &Self::INSTANCE) -> Vec<SymPoint> {
        let SchnorrWitness { privatekey } = witness;
        vec![privatekey * SymPoint::Const(RISTRETTO_BASEPOINT_POINT)]
    }
}
```

A prover and a verifier can then use functions derived by the framework:

```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a random private key
    let rng = &mut rand::rngs::OsRng;
    let sk = Scalar::random(rng);

    // Create witness (secret)
    let witness = SchnorrWitness {
        privatekey: SymScalar::Const(sk),
    };

    // Create instance (public)
    let pk = sk * RISTRETTO_BASEPOINT_POINT;
    let instance = SchnorrInstance {
        pubkey: SymPoint::Const(pk),
    };

    // Generate proof
    let proof = SchnorrIdentityProtocol::prove(&witness, &instance);
    println!("Proof generated: {} bytes", proof.len());

    // Verify proof
    match SchnorrIdentityProtocol::verify(&instance, &proof) {
        Ok(()) => println!("✅ Proof verified successfully!"),
        Err(e) => println!("❌ Proof verification failed: {}", e),
    }

    Ok(())
}
```

## Automatic Specification Generation

The library can automatically generate formal specifications in Markdown+LaTeX format:

```rust
// Generate specification for the Schnorr protocol
let spec = SchnorrIdentityProtocol::spec();
println!("{spec}");
```

This outputs the following spec:

![specification example](https://github.com/user-attachments/assets/558ec655-f2da-42f7-94ca-01d8eacc9b40)
