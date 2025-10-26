use crate::errors::SigmaProofError;

/// Spongefish opts for a minimal error.
/// Informative errors about instance decoding, deserialziation might leak information outside
/// Instance processing errors also happen at a different step
impl From<spongefish::VerificationError> for SigmaProofError {
    fn from(_value: spongefish::VerificationError) -> Self {
        SigmaProofError::TranscriptError
    }
}
