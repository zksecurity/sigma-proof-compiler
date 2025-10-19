use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use std::io::{Read, Write};

pub(crate) struct ProofTranscript {
    state: merlin::Transcript,
    proof: std::io::Cursor<Vec<u8>>,
    is_prover: bool,
}

impl ProofTranscript {
    pub(crate) fn new_prover(label: &'static [u8]) -> Self {
        Self {
            state: merlin::Transcript::new(label),
            proof: std::io::Cursor::new(Vec::new()),
            is_prover: true,
        }
    }

    pub(crate) fn new_verifier(label: &'static [u8], proof: &[u8]) -> Self {
        Self {
            state: merlin::Transcript::new(label),
            proof: std::io::Cursor::new(proof.to_vec()),
            is_prover: false,
        }
    }

    pub(crate) fn common_absorb_scalar(&mut self, label: &'static [u8], scalar: &Scalar) {
        self.state.append_message(label, scalar.as_bytes());
    }

    pub(crate) fn common_absorb_point(&mut self, label: &'static [u8], point: &RistrettoPoint) {
        self.state
            .append_message(label, point.compress().as_bytes());
    }

    pub(crate) fn prover_absorb_scalar(&mut self, label: &'static [u8], scalar: &Scalar) {
        assert!(self.is_prover);
        self.common_absorb_scalar(label, scalar);
        self.proof.write_all(scalar.as_bytes()).unwrap();
    }

    pub(crate) fn verifier_receives_all_scalars(
        &mut self,
        label: &'static [u8],
    ) -> Option<Vec<Scalar>> {
        assert!(!self.is_prover);
        let mut scalars = Vec::new();
        loop {
            let mut buf = [0u8; 32];
            match self.proof.read_exact(&mut buf) {
                Ok(()) => {
                    let scalar = Scalar::from_canonical_bytes(buf).into_option()?;
                    self.common_absorb_scalar(label, &scalar);
                    scalars.push(scalar);
                }
                Err(_) => break,
            }
        }
        Some(scalars)
    }

    pub(crate) fn prover_absorb_point(&mut self, label: &'static [u8], point: &RistrettoPoint) {
        assert!(self.is_prover);
        self.common_absorb_point(label, &point);
        self.proof.write_all(point.compress().as_bytes()).unwrap();
    }

    pub(crate) fn verifier_receive_points(
        &mut self,
        label: &'static [u8],
        count: usize,
    ) -> Option<Vec<RistrettoPoint>> {
        assert!(!self.is_prover);
        let mut points = Vec::with_capacity(count);
        for _ in 0..count {
            let mut buf = [0u8; 32];
            if self.proof.read_exact(&mut buf).is_err() {
                return None;
            }
            let point = CompressedRistretto(buf).decompress()?;
            self.common_absorb_point(label, &point); // TODO: we recompress here :/
            points.push(point);
        }
        Some(points)
    }

    pub(crate) fn challenge(&mut self, label: &'static [u8]) -> Scalar {
        let mut buf = [0u8; 64];
        self.state.challenge_bytes(label, &mut buf);
        Scalar::from_bytes_mod_order_wide(&buf)
    }

    pub(crate) fn finalize(self) -> Vec<u8> {
        self.proof.into_inner()
    }
}
