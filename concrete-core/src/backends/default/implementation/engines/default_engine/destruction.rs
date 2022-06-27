use crate::backends::default::implementation::engines::DefaultEngine;
use crate::backends::default::implementation::entities::{
    Cleartext32, Cleartext64, CleartextVector32, CleartextVector64, GgswCiphertext32,
    GgswCiphertext64, GlweCiphertext32, GlweCiphertext64, GlweCiphertextMutView32,
    GlweCiphertextMutView64, GlweCiphertextVector32, GlweCiphertextVector64, GlweCiphertextView32,
    GlweCiphertextView64, GlweSecretKey32, GlweSecretKey64, GlweSeededCiphertext32,
    GlweSeededCiphertext64, LweBootstrapKey32, LweBootstrapKey64, LweCiphertext32, LweCiphertext64,
    LweCiphertextMutView32, LweCiphertextMutView64, LweCiphertextVector32, LweCiphertextVector64,
    LweCiphertextView32, LweCiphertextView64, LweKeyswitchKey32, LweKeyswitchKey64, LweSecretKey32,
    LweSecretKey64, LweSeededCiphertext32, LweSeededCiphertext64, LweSeededCiphertextVector32,
    LweSeededCiphertextVector64, LweSeededKeyswitchKey32, LweSeededKeyswitchKey64,
    PackingKeyswitchKey32, PackingKeyswitchKey64, Plaintext32, Plaintext64, PlaintextVector32,
    PlaintextVector64,
};
use crate::commons::math::tensor::AsMutTensor;
use crate::prelude::{CleartextF64, CleartextVectorF64, FloatEncoder, FloatEncoderVector};
use crate::specification::engines::{DestructionEngine, DestructionError};

impl DestructionEngine<Cleartext32> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: Cleartext32,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut Cleartext32) {}
}

impl DestructionEngine<Cleartext64> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: Cleartext64,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut Cleartext64) {}
}

impl DestructionEngine<CleartextVector32> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: CleartextVector32,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut CleartextVector32) {}
}

impl DestructionEngine<CleartextVector64> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: CleartextVector64,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut CleartextVector64) {}
}

impl DestructionEngine<Plaintext32> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: Plaintext32,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut Plaintext32) {}
}

impl DestructionEngine<Plaintext64> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: Plaintext64,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut Plaintext64) {}
}

impl DestructionEngine<PlaintextVector32> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: PlaintextVector32,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut PlaintextVector32) {}
}

impl DestructionEngine<PlaintextVector64> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: PlaintextVector64,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut PlaintextVector64) {}
}

impl DestructionEngine<LweCiphertext32> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: LweCiphertext32,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut LweCiphertext32) {}
}

impl DestructionEngine<LweCiphertext64> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: LweCiphertext64,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut LweCiphertext64) {}
}

impl DestructionEngine<LweCiphertextVector32> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: LweCiphertextVector32,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut LweCiphertextVector32) {}
}

impl DestructionEngine<LweCiphertextVector64> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: LweCiphertextVector64,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut LweCiphertextVector64) {}
}

impl DestructionEngine<LweCiphertextView32<'_>> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: LweCiphertextView32<'_>,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut LweCiphertextView32<'_>) {}
}

impl DestructionEngine<LweCiphertextMutView32<'_>> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: LweCiphertextMutView32<'_>,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut LweCiphertextMutView32<'_>) {}
}

impl DestructionEngine<LweCiphertextView64<'_>> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: LweCiphertextView64<'_>,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut LweCiphertextView64<'_>) {}
}

impl DestructionEngine<LweCiphertextMutView64<'_>> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: LweCiphertextMutView64<'_>,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut LweCiphertextMutView64<'_>) {}
}

impl DestructionEngine<LweSeededCiphertext32> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: LweSeededCiphertext32,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut LweSeededCiphertext32) {}
}

impl DestructionEngine<LweSeededCiphertext64> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: LweSeededCiphertext64,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut LweSeededCiphertext64) {}
}

impl DestructionEngine<LweSeededCiphertextVector32> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: LweSeededCiphertextVector32,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut LweSeededCiphertextVector32) {}
}

impl DestructionEngine<LweSeededCiphertextVector64> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: LweSeededCiphertextVector64,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut LweSeededCiphertextVector64) {}
}

impl DestructionEngine<LweSeededKeyswitchKey32> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: LweSeededKeyswitchKey32,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut LweSeededKeyswitchKey32) {}
}

impl DestructionEngine<LweSeededKeyswitchKey64> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: LweSeededKeyswitchKey64,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut LweSeededKeyswitchKey64) {}
}

impl DestructionEngine<GlweCiphertext32> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: GlweCiphertext32,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut GlweCiphertext32) {}
}

impl DestructionEngine<GlweCiphertext64> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: GlweCiphertext64,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut GlweCiphertext64) {}
}

impl DestructionEngine<GlweCiphertextVector32> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: GlweCiphertextVector32,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut GlweCiphertextVector32) {}
}

impl DestructionEngine<GlweCiphertextVector64> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: GlweCiphertextVector64,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut GlweCiphertextVector64) {}
}

impl DestructionEngine<GlweCiphertextView32<'_>> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: GlweCiphertextView32<'_>,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut GlweCiphertextView32<'_>) {}
}

impl DestructionEngine<GlweCiphertextMutView32<'_>> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: GlweCiphertextMutView32<'_>,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut GlweCiphertextMutView32<'_>) {}
}

impl DestructionEngine<GlweCiphertextView64<'_>> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: GlweCiphertextView64<'_>,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut GlweCiphertextView64<'_>) {}
}

impl DestructionEngine<GlweCiphertextMutView64<'_>> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: GlweCiphertextMutView64<'_>,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut GlweCiphertextMutView64<'_>) {}
}

impl DestructionEngine<GgswCiphertext32> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: GgswCiphertext32,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut GgswCiphertext32) {}
}

impl DestructionEngine<GgswCiphertext64> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: GgswCiphertext64,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut GgswCiphertext64) {}
}

impl DestructionEngine<LweBootstrapKey32> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: LweBootstrapKey32,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut LweBootstrapKey32) {}
}

impl DestructionEngine<LweBootstrapKey64> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: LweBootstrapKey64,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut LweBootstrapKey64) {}
}

impl DestructionEngine<LweKeyswitchKey32> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: LweKeyswitchKey32,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut LweKeyswitchKey32) {}
}

impl DestructionEngine<LweKeyswitchKey64> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: LweKeyswitchKey64,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut LweKeyswitchKey64) {}
}

impl DestructionEngine<LweSecretKey32> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: LweSecretKey32,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, entity: &mut LweSecretKey32) {
        entity.0.as_mut_tensor().fill_with_element(0u32);
    }
}

impl DestructionEngine<LweSecretKey64> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: LweSecretKey64,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, entity: &mut LweSecretKey64) {
        entity.0.as_mut_tensor().fill_with_element(0u64);
    }
}

impl DestructionEngine<GlweSecretKey32> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: GlweSecretKey32,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, entity: &mut GlweSecretKey32) {
        entity.0.as_mut_tensor().fill_with_element(0u32);
    }
}

impl DestructionEngine<GlweSecretKey64> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: GlweSecretKey64,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, entity: &mut GlweSecretKey64) {
        entity.0.as_mut_tensor().fill_with_element(0u64);
    }
}

impl DestructionEngine<GlweSeededCiphertext32> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: GlweSeededCiphertext32,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut GlweSeededCiphertext32) {}
}

impl DestructionEngine<GlweSeededCiphertext64> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: GlweSeededCiphertext64,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut GlweSeededCiphertext64) {}
}

impl DestructionEngine<PackingKeyswitchKey32> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: PackingKeyswitchKey32,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, entity: &mut PackingKeyswitchKey32) {
        entity.0.as_mut_tensor().fill_with_element(0u32);
    }
}

impl DestructionEngine<PackingKeyswitchKey64> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: PackingKeyswitchKey64,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) };
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, entity: &mut PackingKeyswitchKey64) {
        entity.0.as_mut_tensor().fill_with_element(0u64);
    }
}

impl DestructionEngine<FloatEncoder> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: FloatEncoder,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) }
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut FloatEncoder) {}
}

impl DestructionEngine<FloatEncoderVector> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: FloatEncoderVector,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) }
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut FloatEncoderVector) {}
}

impl DestructionEngine<CleartextF64> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: CleartextF64,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) }
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, _entity: &mut CleartextF64) {}
}

impl DestructionEngine<CleartextVectorF64> for DefaultEngine {
    fn destroy(
        &mut self,
        mut entity: CleartextVectorF64,
    ) -> Result<(), DestructionError<Self::EngineError>> {
        unsafe { self.destroy_unchecked(&mut entity) }
        Ok(())
    }

    unsafe fn destroy_unchecked(&mut self, entity: &mut CleartextVectorF64) {
        entity.0.as_mut_tensor().fill_with_element(0.0f64);
    }
}
