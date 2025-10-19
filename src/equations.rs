//
// Symbolic
//

use curve25519_dalek::{RistrettoPoint, Scalar};
use std::ops::{Add, Mul, Neg, Sub};

use crate::errors::SigmaProofError;

#[derive(Clone)]
pub enum SymScalar {
    Const(Scalar),
    Var(Option<Scalar>),
    Add(Box<SymScalar>, Box<SymScalar>),
    Sub(Box<SymScalar>, Box<SymScalar>),
    Neg(Box<SymScalar>),
    Mul(Box<SymScalar>, Box<SymScalar>),
}

impl SymScalar {
    pub fn evaluate(&self) -> Result<Scalar, SigmaProofError> {
        match self {
            SymScalar::Const(s) => Ok(*s),
            SymScalar::Var(s) => s.ok_or(SigmaProofError::UninstantiatedScalar),
            SymScalar::Add(s1, s2) => Ok(s1.evaluate()? + s2.evaluate()?),
            SymScalar::Sub(s1, s2) => Ok(s1.evaluate()? - s2.evaluate()?),
            SymScalar::Neg(s) => Ok(-s.evaluate()?),
            SymScalar::Mul(s1, s2) => Ok(s1.evaluate()? * s2.evaluate()?),
        }
    }
}

#[derive(Clone)]
pub enum SymPoint {
    Const(RistrettoPoint),
    Var(Option<RistrettoPoint>),
    Add(Box<SymPoint>, Box<SymPoint>),
    Sub(Box<SymPoint>, Box<SymPoint>),
    Neg(Box<SymPoint>),
    Scale(Box<SymScalar>, Box<SymPoint>),
}

impl SymPoint {
    pub fn evaluate(&self) -> Result<RistrettoPoint, SigmaProofError> {
        match self {
            SymPoint::Const(p) => Ok(p.clone()),
            SymPoint::Var(p) => p.ok_or(SigmaProofError::UninstantiatedPoint),
            SymPoint::Add(p1, p2) => Ok(p1.evaluate()? + p2.evaluate()?),
            SymPoint::Sub(p1, p2) => Ok(p1.evaluate()? - p2.evaluate()?),
            SymPoint::Neg(p) => Ok(-p.evaluate()?),
            SymPoint::Scale(s, p) => Ok(s.evaluate()? * p.evaluate()?),
        }
    }
}

//
// SymScalar arithmetic operators
//

impl Add for SymScalar {
    type Output = SymScalar;
    fn add(self, rhs: SymScalar) -> SymScalar {
        SymScalar::Add(Box::new(self), Box::new(rhs))
    }
}

impl Add<&SymScalar> for SymScalar {
    type Output = SymScalar;
    fn add(self, rhs: &SymScalar) -> SymScalar {
        SymScalar::Add(Box::new(self), Box::new(rhs.clone()))
    }
}

impl Add<SymScalar> for &SymScalar {
    type Output = SymScalar;
    fn add(self, rhs: SymScalar) -> SymScalar {
        SymScalar::Add(Box::new(self.clone()), Box::new(rhs))
    }
}

impl Add<&SymScalar> for &SymScalar {
    type Output = SymScalar;
    fn add(self, rhs: &SymScalar) -> SymScalar {
        SymScalar::Add(Box::new(self.clone()), Box::new(rhs.clone()))
    }
}

impl Sub for SymScalar {
    type Output = SymScalar;
    fn sub(self, rhs: SymScalar) -> SymScalar {
        SymScalar::Sub(Box::new(self), Box::new(rhs))
    }
}

impl Sub<&SymScalar> for SymScalar {
    type Output = SymScalar;
    fn sub(self, rhs: &SymScalar) -> SymScalar {
        SymScalar::Sub(Box::new(self), Box::new(rhs.clone()))
    }
}

impl Sub<SymScalar> for &SymScalar {
    type Output = SymScalar;
    fn sub(self, rhs: SymScalar) -> SymScalar {
        SymScalar::Sub(Box::new(self.clone()), Box::new(rhs))
    }
}

impl Sub<&SymScalar> for &SymScalar {
    type Output = SymScalar;
    fn sub(self, rhs: &SymScalar) -> SymScalar {
        SymScalar::Sub(Box::new(self.clone()), Box::new(rhs.clone()))
    }
}

impl Mul for SymScalar {
    type Output = SymScalar;
    fn mul(self, rhs: SymScalar) -> SymScalar {
        SymScalar::Mul(Box::new(self), Box::new(rhs))
    }
}

impl Mul<&SymScalar> for SymScalar {
    type Output = SymScalar;
    fn mul(self, rhs: &SymScalar) -> SymScalar {
        SymScalar::Mul(Box::new(self), Box::new(rhs.clone()))
    }
}

impl Mul<SymScalar> for &SymScalar {
    type Output = SymScalar;
    fn mul(self, rhs: SymScalar) -> SymScalar {
        SymScalar::Mul(Box::new(self.clone()), Box::new(rhs))
    }
}

impl Mul<&SymScalar> for &SymScalar {
    type Output = SymScalar;
    fn mul(self, rhs: &SymScalar) -> SymScalar {
        SymScalar::Mul(Box::new(self.clone()), Box::new(rhs.clone()))
    }
}

impl Neg for SymScalar {
    type Output = SymScalar;
    fn neg(self) -> SymScalar {
        SymScalar::Neg(Box::new(self))
    }
}

impl Neg for &SymScalar {
    type Output = SymScalar;
    fn neg(self) -> SymScalar {
        SymScalar::Neg(Box::new(self.clone()))
    }
}

// SymPoint arithmetic operators
impl Add for SymPoint {
    type Output = SymPoint;
    fn add(self, rhs: SymPoint) -> SymPoint {
        SymPoint::Add(Box::new(self), Box::new(rhs))
    }
}

impl Add<&SymPoint> for SymPoint {
    type Output = SymPoint;
    fn add(self, rhs: &SymPoint) -> SymPoint {
        SymPoint::Add(Box::new(self), Box::new(rhs.clone()))
    }
}

impl Add<SymPoint> for &SymPoint {
    type Output = SymPoint;
    fn add(self, rhs: SymPoint) -> SymPoint {
        SymPoint::Add(Box::new(self.clone()), Box::new(rhs))
    }
}

impl Add<&SymPoint> for &SymPoint {
    type Output = SymPoint;
    fn add(self, rhs: &SymPoint) -> SymPoint {
        SymPoint::Add(Box::new(self.clone()), Box::new(rhs.clone()))
    }
}

impl Sub for SymPoint {
    type Output = SymPoint;
    fn sub(self, rhs: SymPoint) -> SymPoint {
        SymPoint::Sub(Box::new(self), Box::new(rhs))
    }
}

impl Sub<&SymPoint> for SymPoint {
    type Output = SymPoint;
    fn sub(self, rhs: &SymPoint) -> SymPoint {
        SymPoint::Sub(Box::new(self), Box::new(rhs.clone()))
    }
}

impl Sub<SymPoint> for &SymPoint {
    type Output = SymPoint;
    fn sub(self, rhs: SymPoint) -> SymPoint {
        SymPoint::Sub(Box::new(self.clone()), Box::new(rhs))
    }
}

impl Sub<&SymPoint> for &SymPoint {
    type Output = SymPoint;
    fn sub(self, rhs: &SymPoint) -> SymPoint {
        SymPoint::Sub(Box::new(self.clone()), Box::new(rhs.clone()))
    }
}

impl Neg for SymPoint {
    type Output = SymPoint;
    fn neg(self) -> SymPoint {
        SymPoint::Neg(Box::new(self))
    }
}

impl Neg for &SymPoint {
    type Output = SymPoint;
    fn neg(self) -> SymPoint {
        SymPoint::Neg(Box::new(self.clone()))
    }
}

// SymScalar * SymPoint -> SymPoint
impl Mul<SymPoint> for SymScalar {
    type Output = SymPoint;
    fn mul(self, rhs: SymPoint) -> SymPoint {
        SymPoint::Scale(Box::new(self), Box::new(rhs))
    }
}

impl Mul<&SymPoint> for SymScalar {
    type Output = SymPoint;
    fn mul(self, rhs: &SymPoint) -> SymPoint {
        SymPoint::Scale(Box::new(self), Box::new(rhs.clone()))
    }
}

impl Mul<SymPoint> for &SymScalar {
    type Output = SymPoint;
    fn mul(self, rhs: SymPoint) -> SymPoint {
        SymPoint::Scale(Box::new(self.clone()), Box::new(rhs))
    }
}

impl Mul<&SymPoint> for &SymScalar {
    type Output = SymPoint;
    fn mul(self, rhs: &SymPoint) -> SymPoint {
        SymPoint::Scale(Box::new(self.clone()), Box::new(rhs.clone()))
    }
}

// Scalar * SymPoint -> SymPoint
impl Mul<SymPoint> for Scalar {
    type Output = SymPoint;
    fn mul(self, rhs: SymPoint) -> SymPoint {
        SymPoint::Scale(Box::new(SymScalar::Const(self)), Box::new(rhs))
    }
}

impl Mul<&SymPoint> for Scalar {
    type Output = SymPoint;
    fn mul(self, rhs: &SymPoint) -> SymPoint {
        SymPoint::Scale(Box::new(SymScalar::Const(self)), Box::new(rhs.clone()))
    }
}

impl Mul<SymPoint> for &Scalar {
    type Output = SymPoint;
    fn mul(self, rhs: SymPoint) -> SymPoint {
        SymPoint::Scale(Box::new(SymScalar::Const(*self)), Box::new(rhs))
    }
}

impl Mul<&SymPoint> for &Scalar {
    type Output = SymPoint;
    fn mul(self, rhs: &SymPoint) -> SymPoint {
        SymPoint::Scale(Box::new(SymScalar::Const(*self)), Box::new(rhs.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

    #[test]
    fn test_symscalar_operators() {
        let a = SymScalar::Const(Scalar::from(5u64));
        let b = SymScalar::Const(Scalar::from(3u64));

        // Test addition
        let sum = &a + &b;
        assert_eq!(sum.evaluate().unwrap(), Scalar::from(8u64));

        // Test subtraction
        let diff = &a - &b;
        assert_eq!(diff.evaluate().unwrap(), Scalar::from(2u64));

        // Test multiplication
        let product = &a * &b;
        assert_eq!(product.evaluate().unwrap(), Scalar::from(15u64));

        // Test negation
        let neg_a = -&a;
        assert_eq!(neg_a.evaluate().unwrap(), -Scalar::from(5u64));
    }

    #[test]
    fn test_sympoint_operators() {
        let scalar_2 = SymScalar::Const(Scalar::from(2u64));
        let scalar_3 = SymScalar::Const(Scalar::from(3u64));

        let point_a = SymPoint::Const(RISTRETTO_BASEPOINT_POINT);
        let point_b = scalar_2 * &point_a; // 2 * G
        let point_c = scalar_3 * &point_a; // 3 * G

        // Test point addition: (2*G) + (3*G) = 5*G
        let sum = &point_b + &point_c;
        let expected = Scalar::from(5u64) * RISTRETTO_BASEPOINT_POINT;
        assert_eq!(sum.evaluate().unwrap(), expected);

        // Test point subtraction: (3*G) - (2*G) = G
        let diff = &point_c - &point_b;
        assert_eq!(diff.evaluate().unwrap(), RISTRETTO_BASEPOINT_POINT);

        // Test scalar multiplication with plain Scalar
        let scaled = Scalar::from(4u64) * &point_a;
        let expected_scaled = Scalar::from(4u64) * RISTRETTO_BASEPOINT_POINT;
        assert_eq!(scaled.evaluate().unwrap(), expected_scaled);
    }

    #[test]
    fn test_mixed_operations() {
        let a = SymScalar::Const(Scalar::from(2u64));
        let b = SymScalar::Const(Scalar::from(3u64));
        let point = SymPoint::Const(RISTRETTO_BASEPOINT_POINT);

        // Test: (2 + 3) * G = 5 * G
        let scalar_sum = &a + &b;
        let result = scalar_sum * &point;
        let expected = Scalar::from(5u64) * RISTRETTO_BASEPOINT_POINT;
        assert_eq!(result.evaluate().unwrap(), expected);
    }
}
