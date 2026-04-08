pub mod error;
pub mod input_builder;
pub mod pipeline;
pub mod poseidon2;
pub mod types;

pub use error::{Error, Result};
pub use pipeline::{run_pipeline, PipelineResult};
pub use types::{AttestConfig, FieldHex, Stage};
