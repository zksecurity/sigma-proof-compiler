use crate::{
    absorb::{SymInstance, SymPoint, SymScalar, SymWitness},
    compiler::SigmaProof,
};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

pub struct SchnorrIdentityProtocol;

#[derive(SymWitness, Clone)]
pub struct SchnorrWitness {
    privatekey: SymScalar,
}

#[derive(SymInstance, Clone)]
pub struct SchnorrInstance {
    pubkey: SymPoint,
}

impl SigmaProof for SchnorrIdentityProtocol {
    const LABEL: &'static [u8] = b"schnorr-identity-protocol";

    type WITNESS = SchnorrWitness;
    type INSTANCE = SchnorrInstance;

    fn f(instance: &Self::INSTANCE) -> Vec<SymPoint> {
        let Self::INSTANCE { pubkey } = instance.clone();
        vec![pubkey]
    }

    fn psi(witness: &Self::WITNESS, _instance: &Self::INSTANCE) -> Vec<SymPoint> {
        let Self::WITNESS { privatekey } = witness.clone();
        vec![privatekey * SymPoint::Const(RISTRETTO_BASEPOINT_POINT)]
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::Scalar;

    use super::*;

    #[test]
    fn test_schnorr_identity_protocol() {
        let rng = &mut rand::rngs::OsRng;
        let sk = Scalar::random(rng);
        let witness = SchnorrWitness {
            privatekey: SymScalar::Const(sk),
        };

        let pk = sk * RISTRETTO_BASEPOINT_POINT;
        let instance = SchnorrInstance {
            pubkey: SymPoint::Const(pk),
        };

        let proof = SchnorrIdentityProtocol::prove(&witness, &instance).unwrap();

        println!("Schnorr proof: {:?}", proof);

        SchnorrIdentityProtocol::verify(&instance, &proof).unwrap();
    }

    #[test]
    fn test_schnorr_spec_generation() {
        let spec = SchnorrIdentityProtocol::spec();
        println!("{spec}");
    }
}
