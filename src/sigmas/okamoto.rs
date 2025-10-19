use crate::{
    absorb::{SymInstance, SymPoint, SymScalar, SymWitness},
    compiler::SigmaProof,
    sigmas::{G, H},
};

pub struct Okamoto;

#[derive(SymWitness, Clone)]
pub struct OkamotoWitness {
    x: SymScalar,
    y: SymScalar,
}

#[derive(SymInstance, Clone)]
pub struct OkamotoInstance {
    point: SymPoint,
}

impl SigmaProof for Okamoto {
    const LABEL: &'static [u8] = b"okamoto-protocol";

    type WITNESS = OkamotoWitness;
    type INSTANCE = OkamotoInstance;

    fn f(instance: &Self::INSTANCE) -> Vec<SymPoint> {
        let Self::INSTANCE { point } = instance.clone();
        vec![point]
    }

    fn psi(witness: &Self::WITNESS, _instance: &Self::INSTANCE) -> Vec<SymPoint> {
        let Self::WITNESS { x, y } = witness.clone();
        vec![(x * G) + (y * H.clone())]
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::Scalar;

    use super::*;

    #[test]
    fn test_okamoto_identity_protocol() {
        let rng = &mut rand::rngs::OsRng;
        let sk = Scalar::random(rng);
        let witness = OkamotoWitness {
            x: SymScalar::Const(sk),
            y: SymScalar::Const(sk),
        };

        let instance = OkamotoInstance {
            point: (sk * G) + (sk * H.clone()),
        };

        let proof = Okamoto::prove(&witness, &instance).unwrap();

        println!("Okamoto proof: {:?}", proof);

        Okamoto::verify(&instance, &proof).unwrap();
    }

    #[test]
    fn test_okamoto_spec_generation() {
        let spec = Okamoto::spec();
        println!("{spec}");
    }
}
