use crate::specification::engines::sealed::AbstractEngineSeal;
use crate::specification::engines::AbstractEngine;
use std::error::Error;
use std::fmt::{Display, Formatter};

/// The error which can occur in the execution of FHE operations, due to the fftw implementation.
#[derive(Debug)]
pub enum FftwSerializationError {
    Serialization(bincode::Error),
    Deserialization(bincode::Error),
    UnsupportedVersion,
}

impl Display for FftwSerializationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            FftwSerializationError::Serialization(bincode_error) => {
                write!(f, "Failed to serialize entity: {}", bincode_error)
            }
            FftwSerializationError::Deserialization(bincode_error) => {
                write!(f, "Failed to deserialize entity: {}", bincode_error)
            }
            FftwSerializationError::UnsupportedVersion => {
                write!(
                    f,
                    "The version used to serialize the entity is not supported."
                )
            }
        }
    }
}

impl Error for FftwSerializationError {}

/// The serialization engine exposed by the fftw backend.
pub struct FftwSerializationEngine;

impl AbstractEngineSeal for FftwSerializationEngine {}

impl AbstractEngine for FftwSerializationEngine {
    type EngineError = FftwSerializationError;
    type Parameters = ();

    fn new(_parameters: Self::Parameters) -> Result<Self, Self::EngineError> {
        Ok(FftwSerializationEngine)
    }
}

mod entity_deserialization;
mod entity_serialization;
