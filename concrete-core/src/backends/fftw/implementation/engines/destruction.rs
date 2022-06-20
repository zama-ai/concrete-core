use crate::backends::fftw::engines::FftwEngine;
use crate::backends::fftw::entities::{
    FftwFourierGgswCiphertext32, FftwFourierGgswCiphertext64, FftwFourierGlweCiphertext32,
    FftwFourierGlweCiphertext64, FftwFourierGlweTensorProductSecretKey32,
    FftwFourierGlweTensorProductSecretKey64, FftwFourierLweBootstrapKey32,
    FftwFourierLweBootstrapKey64,
};
use crate::prelude::{
    FftwFourierGlweTensorProductCiphertext32, FftwFourierGlweTensorProductCiphertext64,
};
use crate::specification::engines::{DestructionEngine, DestructionError};

impl DestructionEngine<FftwFourierGlweCiphertext32> for FftwEngine {
    fn destroy(
        &mut self,
        mut entity: FftwFourierGlweCiphertext32,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut FftwFourierGlweCiphertext32) {}
}

impl DestructionEngine<FftwFourierGlweCiphertext64> for FftwEngine {
    fn destroy(
        &mut self,
        mut entity: FftwFourierGlweCiphertext64,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut FftwFourierGlweCiphertext64) {}
}

impl DestructionEngine<FftwFourierGlweTensorProductCiphertext32> for FftwEngine {
    fn destroy(
        &mut self,
        mut entity: FftwFourierGlweTensorProductCiphertext32,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut FftwFourierGlweTensorProductCiphertext32) {
    }
}

impl DestructionEngine<FftwFourierGlweTensorProductCiphertext64> for FftwEngine {
    fn destroy(
        &mut self,
        mut entity: FftwFourierGlweTensorProductCiphertext64,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut FftwFourierGlweTensorProductCiphertext64) {
    }
}

impl DestructionEngine<FftwFourierGgswCiphertext32> for FftwEngine {
    fn destroy(
        &mut self,
        mut entity: FftwFourierGgswCiphertext32,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut FftwFourierGgswCiphertext32) {}
}

impl DestructionEngine<FftwFourierGgswCiphertext64> for FftwEngine {
    fn destroy(
        &mut self,
        mut entity: FftwFourierGgswCiphertext64,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut FftwFourierGgswCiphertext64) {}
}

impl DestructionEngine<FftwFourierLweBootstrapKey32> for FftwEngine {
    fn destroy(
        &mut self,
        mut entity: FftwFourierLweBootstrapKey32,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut FftwFourierLweBootstrapKey32) {}
}

impl DestructionEngine<FftwFourierLweBootstrapKey64> for FftwEngine {
    fn destroy(
        &mut self,
        mut entity: FftwFourierLweBootstrapKey64,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut FftwFourierLweBootstrapKey64) {}
}

impl DestructionEngine<FftwFourierGlweTensorProductSecretKey32> for FftwEngine {
    fn destroy(
        &mut self,
        mut entity: FftwFourierGlweTensorProductSecretKey32,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut FftwFourierGlweTensorProductSecretKey32) {}
}

impl DestructionEngine<FftwFourierGlweTensorProductSecretKey64> for FftwEngine {
    fn destroy(
        &mut self,
        mut entity: FftwFourierGlweTensorProductSecretKey64,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut FftwFourierGlweTensorProductSecretKey64) {}
}
