use crate::backends::cuda::implementation::engines::CudaEngine;
use crate::backends::cuda::implementation::entities::{
    CudaFourierLweBootstrapKey32, CudaFourierLweBootstrapKey64, CudaGlweCiphertext32,
    CudaGlweCiphertext64, CudaGlweCiphertextVector32, CudaGlweCiphertextVector64,
    CudaLweCiphertext32, CudaLweCiphertext64, CudaLweCiphertextVector32, CudaLweCiphertextVector64,
    CudaLweKeyswitchKey32, CudaLweKeyswitchKey64,
};
use crate::backends::cuda::private::device::GpuIndex;
use crate::specification::engines::{DestructionEngine, DestructionError};

macro_rules! drop_entity {
    ($s:ident, $e:ident) => {
        for gpu_index in 0..$s.get_number_of_gpus() {
            $s.streams[gpu_index]
                .drop($e.0.get_ptr(GpuIndex(gpu_index as u32)).0)
                .unwrap();
        }
    };
}

impl DestructionEngine<CudaLweCiphertext32> for CudaEngine {
    fn destroy(
        &mut self,
        mut entity: CudaLweCiphertext32,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, entity: &mut CudaLweCiphertext32) {
        // Here deallocate the Cuda memory
        self.streams[0].drop(entity.0.get_ptr().0).unwrap();
    }
}

impl DestructionEngine<CudaLweCiphertext64> for CudaEngine {
    fn destroy(
        &mut self,
        mut entity: CudaLweCiphertext64,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, entity: &mut CudaLweCiphertext64) {
        // Here deallocate the Cuda memory
        self.streams[0].drop(entity.0.get_ptr().0).unwrap();
    }
}

impl DestructionEngine<CudaGlweCiphertext32> for CudaEngine {
    fn destroy(
        &mut self,
        mut entity: CudaGlweCiphertext32,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, entity: &mut CudaGlweCiphertext32) {
        // Here deallocate the Cuda memory
        self.streams[0].drop(entity.0.get_ptr().0).unwrap();
    }
}

impl DestructionEngine<CudaGlweCiphertext64> for CudaEngine {
    fn destroy(
        &mut self,
        mut entity: CudaGlweCiphertext64,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, entity: &mut CudaGlweCiphertext64) {
        // Here deallocate the Cuda memory
        self.streams[0].drop(entity.0.get_ptr().0).unwrap();
    }
}

impl DestructionEngine<CudaLweCiphertextVector32> for CudaEngine {
    fn destroy(
        &mut self,
        mut entity: CudaLweCiphertextVector32,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, entity: &mut CudaLweCiphertextVector32) {
        // Here deallocate the Cuda memory
        drop_entity!(self, entity);
    }
}

impl DestructionEngine<CudaLweCiphertextVector64> for CudaEngine {
    fn destroy(
        &mut self,
        mut entity: CudaLweCiphertextVector64,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, entity: &mut CudaLweCiphertextVector64) {
        // Here deallocate the Cuda memory
        drop_entity!(self, entity);
    }
}

impl DestructionEngine<CudaGlweCiphertextVector32> for CudaEngine {
    fn destroy(
        &mut self,
        mut entity: CudaGlweCiphertextVector32,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, entity: &mut CudaGlweCiphertextVector32) {
        // Here deallocate the Cuda memory
        drop_entity!(self, entity);
    }
}

impl DestructionEngine<CudaGlweCiphertextVector64> for CudaEngine {
    fn destroy(
        &mut self,
        mut entity: CudaGlweCiphertextVector64,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, entity: &mut CudaGlweCiphertextVector64) {
        // Here deallocate the Cuda memory
        drop_entity!(self, entity);
    }
}

impl DestructionEngine<CudaFourierLweBootstrapKey32> for CudaEngine {
    fn destroy(
        &mut self,
        mut entity: CudaFourierLweBootstrapKey32,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, entity: &mut CudaFourierLweBootstrapKey32) {
        // Here deallocate the Cuda memory
        drop_entity!(self, entity);
    }
}

impl DestructionEngine<CudaFourierLweBootstrapKey64> for CudaEngine {
    fn destroy(
        &mut self,
        mut entity: CudaFourierLweBootstrapKey64,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, entity: &mut CudaFourierLweBootstrapKey64) {
        // Here deallocate the Cuda memory
        drop_entity!(self, entity);
    }
}

impl DestructionEngine<CudaLweKeyswitchKey32> for CudaEngine {
    fn destroy(
        &mut self,
        mut entity: CudaLweKeyswitchKey32,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, entity: &mut CudaLweKeyswitchKey32) {
        // Here deallocate the Cuda memory
        drop_entity!(self, entity);
    }
}

impl DestructionEngine<CudaLweKeyswitchKey64> for CudaEngine {
    fn destroy(
        &mut self,
        mut entity: CudaLweKeyswitchKey64,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, entity: &mut CudaLweKeyswitchKey64) {
        // Here deallocate the Cuda memory
        drop_entity!(self, entity);
    }
}
