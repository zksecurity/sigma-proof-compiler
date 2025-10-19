use curve25519_dalek::{RistrettoPoint, Scalar};
use rand_core::CryptoRngCore;

use crate::errors::{SigmaProofError, SigmaProofResult};

//
// Traits only available in this crate
//

pub(crate) mod sealed_witness {
    pub trait Sealed {}

    impl Sealed for super::SymScalar {}
}

pub(crate) mod sealed_instance {
    pub trait Sealed {}

    impl Sealed for super::SymScalar {}
    impl Sealed for super::SymPoint {}
}

pub trait SymWitness: sealed_witness::Sealed {
    fn rand<R: CryptoRngCore + ?Sized>(rng: &mut R) -> Self;
    fn values(&self) -> SigmaProofResult<Vec<Scalar>>;
    fn from_values(scalars: &[Scalar]) -> SigmaProofResult<Self>
    where
        Self: Sized;
    fn num_scalars() -> usize;
    fn get_var_name(index: usize) -> &'static str;
}

pub trait SymInstance: sealed_instance::Sealed {
    fn num_scalars() -> usize;
    fn num_points() -> usize;
    fn from_values(scalars: &[Scalar], points: &[RistrettoPoint]) -> SigmaProofResult<Self>
    where
        Self: Sized;
    fn get_field_names() -> Vec<&'static str>;
    fn points(&self) -> Vec<SymPoint>;
    fn scalars(&self) -> Vec<SymScalar>;
}

//
// Implementations
//

pub use crate::equations::{SymPoint, SymScalar};
pub use sigma_proof_compiler_derive::{SymInstance, SymWitness};

impl SymWitness for SymScalar {
    fn rand<R: CryptoRngCore + ?Sized>(rng: &mut R) -> Self {
        SymScalar::Const(Scalar::random(rng))
    }

    fn values(&self) -> SigmaProofResult<Vec<Scalar>> {
        match self {
            SymScalar::Var(None) => Err(SigmaProofError::UninstantiatedScalar),
            _ => Ok(vec![self.evaluate()?]),
        }
    }

    fn from_values(scalars: &[Scalar]) -> SigmaProofResult<Self> {
        if scalars.len() == 1 {
            Ok(SymScalar::Var(Some(scalars[0])))
        } else {
            Err(SigmaProofError::TooManyScalars {
                expected: 1,
                actual: scalars.len(),
            })
        }
    }

    fn num_scalars() -> usize {
        1
    }

    fn get_var_name(index: usize) -> &'static str {
        if index == 0 {
            "s"
        } else {
            "unknown"
        }
    }
}

impl SymInstance for SymScalar {
    fn num_scalars() -> usize {
        1
    }

    fn num_points() -> usize {
        0
    }

    fn from_values(scalars: &[Scalar], points: &[RistrettoPoint]) -> SigmaProofResult<Self> {
        if scalars.len() == 1 && points.is_empty() {
            Ok(SymScalar::Const(scalars[0]))
        } else {
            Err(SigmaProofError::TooManyScalars {
                expected: 1,
                actual: scalars.len(),
            })
        }
    }

    fn get_field_names() -> Vec<&'static str> {
        vec!["scalar"]
    }

    fn points(&self) -> Vec<SymPoint> {
        vec![]
    }

    fn scalars(&self) -> Vec<SymScalar> {
        vec![self.clone()]
    }
}

impl SymInstance for SymPoint {
    fn num_scalars() -> usize {
        0
    }

    fn num_points() -> usize {
        1
    }

    fn from_values(scalars: &[Scalar], points: &[RistrettoPoint]) -> SigmaProofResult<Self> {
        if scalars.is_empty() && points.len() == 1 {
            Ok(SymPoint::Const(points[0]))
        } else {
            Err(SigmaProofError::TooManyScalars {
                expected: 0,
                actual: scalars.len(),
            })
        }
    }

    fn get_field_names() -> Vec<&'static str> {
        vec!["point"]
    }

    fn points(&self) -> Vec<SymPoint> {
        vec![self.clone()]
    }

    fn scalars(&self) -> Vec<SymScalar> {
        vec![]
    }
}
