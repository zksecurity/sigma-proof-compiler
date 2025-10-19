use crate::{
    absorb::{SymInstance, SymPoint, SymScalar, SymWitness},
    compiler::SigmaProof,
    sigmas::H,
};

pub struct ZeroCheckProtocol;

#[derive(SymWitness, Clone)]
pub struct ZeroCheckWitness {
    secret_key: SymScalar,
}

#[derive(SymInstance, Clone)]
pub struct ZeroCheckInstance {
    pubkey: SymPoint,
    commitment: SymPoint,
    handle: SymPoint,
}

impl SigmaProof for ZeroCheckProtocol {
    const LABEL: &'static [u8] = b"zero-check-protocol";

    type WITNESS = ZeroCheckWitness;
    type INSTANCE = ZeroCheckInstance;

    fn f(instance: &Self::INSTANCE) -> Vec<SymPoint> {
        let Self::INSTANCE {
            pubkey: _,
            commitment,
            handle: _,
        } = instance.clone();
        vec![SymPoint::Const(*H), commitment]
    }

    fn psi(witness: &Self::WITNESS, instance: &Self::INSTANCE) -> Vec<SymPoint> {
        let ZeroCheckWitness { secret_key } = witness;

        vec![
            secret_key * instance.pubkey.clone(), // = H
            secret_key * instance.handle.clone(), // = rH = enc(0, r)
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::Scalar;

    #[test]
    fn test_zero_check_protocol() {
        let rng = &mut rand::rngs::OsRng;

        // Generate a random secret key
        let secret = Scalar::random(rng);
        let witness = ZeroCheckWitness {
            secret_key: SymScalar::Const(secret),
        };
        let public_key = secret.invert() * *H;

        // generate opening
        let r = Scalar::random(rng);

        // zero_commitment = 0 * G + r * H
        let zero_commitment = r * *H;

        // Compute the decrypt handle D = s*P
        let handle = r * public_key;

        let instance = ZeroCheckInstance {
            pubkey: SymPoint::Const(public_key),
            commitment: SymPoint::Const(zero_commitment),
            handle: SymPoint::Const(handle),
        };

        // Generate and verify proof
        let proof = ZeroCheckProtocol::prove(&witness, &instance).unwrap();
        println!("Zero check proof: {} bytes", proof.len());

        ZeroCheckProtocol::verify(&instance, &proof).unwrap();
    }

    #[test]
    fn test_zero_check_spec_generation() {
        let spec = ZeroCheckProtocol::spec();
        println!("{spec}");
    }

    #[test]
    fn test_zero_check_invalid_proof() {
        let rng = &mut rand::rngs::OsRng;

        // Generate a valid witness
        let secret = Scalar::random(rng);
        let witness = ZeroCheckWitness {
            secret_key: SymScalar::Const(secret),
        };

        // Generate public key
        let public_key_scalar = Scalar::random(rng);
        let public_key = public_key_scalar * RISTRETTO_BASEPOINT_POINT;

        // Generate INVALID instance (commitment and handle don't match the secret)
        let wrong_secret = Scalar::random(rng);
        let h_generator = RISTRETTO_BASEPOINT_POINT;
        let commitment = wrong_secret * h_generator; // Wrong commitment
        let handle = wrong_secret * public_key; // Wrong handle

        let instance = ZeroCheckInstance {
            pubkey: SymPoint::Const(public_key),
            commitment: SymPoint::Const(commitment),
            handle: SymPoint::Const(handle),
        };

        // Generate proof with mismatched witness and instance
        let proof = ZeroCheckProtocol::prove(&witness, &instance).unwrap();

        // Verification should fail
        assert!(ZeroCheckProtocol::verify(&instance, &proof).is_err());
    }
}
