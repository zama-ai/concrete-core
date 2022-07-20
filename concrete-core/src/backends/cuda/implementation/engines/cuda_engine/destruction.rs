use crate::backends::cuda::implementation::engines::CudaEngine;
use crate::backends::cuda::implementation::entities::{
    CudaFourierLweBootstrapKey32, CudaFourierLweBootstrapKey64, CudaGlweCiphertext32,
    CudaGlweCiphertext64, CudaGlweCiphertextVector32, CudaGlweCiphertextVector64,
    CudaLweCiphertext32, CudaLweCiphertext64, CudaLweCiphertextVector32, CudaLweCiphertextVector64,
    CudaLweKeyswitchKey32, CudaLweKeyswitchKey64,
};
use crate::specification::engines::{DestructionEngine, DestructionError};

impl DestructionEngine<CudaLweCiphertext32> for CudaEngine {
    fn destroy(
        &mut self,
        _entity: CudaLweCiphertext32,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut CudaLweCiphertext32) {}
}

impl DestructionEngine<CudaLweCiphertext64> for CudaEngine {
    fn destroy(
        &mut self,
        _entity: CudaLweCiphertext64,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut CudaLweCiphertext64) {}
}

impl DestructionEngine<CudaGlweCiphertext32> for CudaEngine {
    fn destroy(
        &mut self,
        _entity: CudaGlweCiphertext32,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut CudaGlweCiphertext32) {}
}

impl DestructionEngine<CudaGlweCiphertext64> for CudaEngine {
    fn destroy(
        &mut self,
        _entity: CudaGlweCiphertext64,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut CudaGlweCiphertext64) {}
}

impl DestructionEngine<CudaLweCiphertextVector32> for CudaEngine {
    fn destroy(
        &mut self,
        _entity: CudaLweCiphertextVector32,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut CudaLweCiphertextVector32) {}
}

impl DestructionEngine<CudaLweCiphertextVector64> for CudaEngine {
    fn destroy(
        &mut self,
        _entity: CudaLweCiphertextVector64,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut CudaLweCiphertextVector64) {}
}

impl DestructionEngine<CudaGlweCiphertextVector32> for CudaEngine {
    fn destroy(
        &mut self,
        _entity: CudaGlweCiphertextVector32,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut CudaGlweCiphertextVector32) {}
}

impl DestructionEngine<CudaGlweCiphertextVector64> for CudaEngine {
    fn destroy(
        &mut self,
        _entity: CudaGlweCiphertextVector64,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut CudaGlweCiphertextVector64) {}
}

impl DestructionEngine<CudaFourierLweBootstrapKey32> for CudaEngine {
    fn destroy(
        &mut self,
        _entity: CudaFourierLweBootstrapKey32,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut CudaFourierLweBootstrapKey32) {}
}

impl DestructionEngine<CudaFourierLweBootstrapKey64> for CudaEngine {
    fn destroy(
        &mut self,
        _entity: CudaFourierLweBootstrapKey64,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut CudaFourierLweBootstrapKey64) {}
}

impl DestructionEngine<CudaLweKeyswitchKey32> for CudaEngine {
    fn destroy(
        &mut self,
        _entity: CudaLweKeyswitchKey32,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut CudaLweKeyswitchKey32) {}
}

impl DestructionEngine<CudaLweKeyswitchKey64> for CudaEngine {
    fn destroy(
        &mut self,
        _entity: CudaLweKeyswitchKey64,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut CudaLweKeyswitchKey64) {}
}
