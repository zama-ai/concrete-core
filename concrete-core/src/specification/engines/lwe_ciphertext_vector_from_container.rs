use super::engine_error;
use crate::prelude::{LweCiphertextEntity, LweCiphertextVectorEntity};
use crate::specification::engines::AbstractEngine;

engine_error! {
    LweCiphertextVectorFromContainerError for LweCiphertextVectorFromContainerEngine @
}

pub trait LweCiphertextVectorFromContainerEngine<Input, Output>: AbstractEngine
where
    Input: LweCiphertextEntity,
    Output: LweCiphertextVectorEntity,
{
    fn create_vector_from_container(
        &mut self,
        input: &[Input],
    ) -> Result<Output, LweCiphertextVectorFromContainerError<Self::EngineError>>;

    unsafe fn create_vector_from_container_unchecked(&mut self, input: &[Input]) -> Output;
}
