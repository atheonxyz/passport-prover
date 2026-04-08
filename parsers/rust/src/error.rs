use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("failed to load prover from {path}")]
    ProverLoad {
        path: PathBuf,
        #[source]
        source: anyhow::Error,
    },

    #[error("stage {stage} proof generation failed")]
    Proving {
        stage: u8,
        #[source]
        source: anyhow::Error,
    },

    #[error("circuit has no public outputs")]
    NoPublicOutputs,

    #[error("invalid field-element hex: {value}")]
    InvalidFieldHex { value: String },

    #[error("JSON serialization failed")]
    JsonSerialization(#[source] serde_json::Error),

    #[error("poseidon2 permutation failed")]
    Poseidon2Permutation,

    #[error("required config field missing: {field}")]
    MissingConfigField { field: &'static str },

    #[error("JSON format unavailable for ABI parsing")]
    JsonFormatUnavailable,

    #[error("failed to parse circuit inputs from JSON")]
    InputParse(#[source] anyhow::Error),

    #[error("passport input error: {0}")]
    Passport(String),
}

pub type Result<T> = std::result::Result<T, Error>;
