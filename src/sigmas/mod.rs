use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, RistrettoPoint};

use crate::absorb::SymPoint;

pub mod chaum;
pub mod okamoto;
pub mod schnorr;
pub mod zero;

pub const G: SymPoint = SymPoint::WellKnownConst("G", RISTRETTO_BASEPOINT_POINT);

// TODO: replace with a more acceptable point?
pub static H: std::sync::LazyLock<SymPoint> = std::sync::LazyLock::new(|| {
    SymPoint::WellKnownConst(
        "H",
        RistrettoPoint::from_uniform_bytes(&[
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
            46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
        ]),
    )
});
