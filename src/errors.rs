use thiserror::Error;

#[derive(Error, Debug)]
pub enum SigmaProofError {
    #[error("SymScalar is not instantiated (contains Var(None))")]
    UninstantiatedScalar,

    #[error("SymPoint is not instantiated (contains Var(None))")]
    UninstantiatedPoint,

    #[error("Failed to deserialize SymWitness: insufficient scalars provided")]
    InsufficientScalars,

    #[error("Failed to deserialize SymInstance: insufficient points provided")]
    InsufficientPoints,

    #[error("Failed to deserialize SymWitness: too many scalars provided (expected {expected}, got {actual})")]
    TooManyScalars { expected: usize, actual: usize },

    #[error("Field '{field}' failed to deserialize")]
    FieldDeserializationFailed { field: String },

    #[error("Proof verification failed: equation check failed")]
    EquationCheckFailed,

    #[error("Issue with proof parameters: psi output length != f output length")]
    PsiOutputLengthMismatch,

    #[error("There are leftover bytes in the proof")]
    TranscriptFinalizationFailed,

    #[error("Transcript error")]
    TranscriptError,

    #[error("Invalid scalar values")]
    InvalidScalarValues,
}

pub type SigmaProofResult<T> = Result<T, SigmaProofError>;
