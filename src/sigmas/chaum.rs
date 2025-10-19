use crate::{
    absorb::{SymInstance, SymPoint, SymScalar, SymWitness},
    compiler::SigmaProof,
    sigmas::{G, H},
};

pub struct Chaum;

#[derive(SymWitness, Clone)]
pub struct ChaumWitness {
    x: SymScalar,
}

#[derive(SymInstance, Clone)]
pub struct ChaumInstance {
    point1: SymPoint,
    point2: SymPoint,
}

impl SigmaProof for Chaum {
    const LABEL: &'static [u8] = b"chaum-protocol";

    type WITNESS = ChaumWitness;
    type INSTANCE = ChaumInstance;

    fn f(instance: &Self::INSTANCE) -> Vec<SymPoint> {
        let Self::INSTANCE { point1, point2 } = instance.clone();
        vec![point1, point2]
    }

    fn psi(witness: &Self::WITNESS, _instance: &Self::INSTANCE) -> Vec<SymPoint> {
        let Self::WITNESS { x } = witness.clone();
        vec![&x * G, &x * H.clone()]
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::Scalar;

    use super::*;

    #[test]
    fn test_chaum_identity_protocol() {
        let rng = &mut rand::rngs::OsRng;
        let sk = Scalar::random(rng);
        let witness = ChaumWitness {
            x: SymScalar::Const(sk),
        };

        let instance = ChaumInstance {
            point1: sk * G,
            point2: sk * H.clone(),
        };

        let proof = Chaum::prove(&witness, &instance).unwrap();

        println!("Chaum proof: {:?}", proof);

        Chaum::verify(&instance, &proof).unwrap();
    }

    #[test]
    fn test_chaum_spec_generation() {
        let spec = Chaum::spec();
        println!("{spec}");
    }
}
