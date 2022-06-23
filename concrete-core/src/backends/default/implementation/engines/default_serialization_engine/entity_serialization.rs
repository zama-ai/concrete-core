#![allow(clippy::missing_safety_doc)]
use crate::commons::crypto::bootstrap::StandardBootstrapKey as ImplStandardBootstrapKey;
use crate::commons::crypto::encoding::{
    Cleartext as ImplCleartext, CleartextList as ImplCleartextList, Plaintext as ImplPlaintext,
    PlaintextList as ImplPlaintextList,
};
use crate::commons::crypto::ggsw::StandardGgswCiphertext as ImplStandardGgswCiphertext;
use crate::commons::crypto::glwe::{
    GlweCiphertext as ImplGlweCiphertext, GlweList as ImplGlweList,
    PackingKeyswitchKey as ImplPackingKeyswitchKey,
};
use crate::commons::crypto::lwe::{
    LweCiphertext as ImplLweCiphertext, LweKeyswitchKey as ImplLweKeyswitchKey,
    LweList as ImplLweList, LweSeededCiphertext as ImplLweSeededCiphertext,
};
use crate::commons::crypto::secret::{
    GlweSecretKey as ImplGlweSecretKey, LweSecretKey as ImplLweSecretKey,
};
use crate::prelude::{
    Cleartext32, Cleartext32Version, Cleartext64, Cleartext64Version, CleartextVector32,
    CleartextVector32Version, CleartextVector64, CleartextVector64Version,
    DefaultSerializationEngine, DefaultSerializationError, EntitySerializationEngine,
    EntitySerializationError, GgswCiphertext32, GgswCiphertext32Version, GgswCiphertext64,
    GgswCiphertext64Version, GlweCiphertext32, GlweCiphertext32Version, GlweCiphertext64,
    GlweCiphertext64Version, GlweCiphertextMutView32, GlweCiphertextMutView64,
    GlweCiphertextVector32, GlweCiphertextVector32Version, GlweCiphertextVector64,
    GlweCiphertextVector64Version, GlweCiphertextView32, GlweCiphertextView64, GlweSecretKey32,
    GlweSecretKey32Version, GlweSecretKey64, GlweSecretKey64Version, LweBootstrapKey32,
    LweBootstrapKey32Version, LweBootstrapKey64, LweBootstrapKey64Version, LweCiphertext32,
    LweCiphertext32Version, LweCiphertext64, LweCiphertext64Version, LweCiphertextMutView32,
    LweCiphertextMutView64, LweCiphertextVector32, LweCiphertextVector32Version,
    LweCiphertextVector64, LweCiphertextVector64Version, LweCiphertextView32, LweCiphertextView64,
    LweKeyswitchKey32, LweKeyswitchKey32Version, LweKeyswitchKey64, LweKeyswitchKey64Version,
    LweSecretKey32, LweSecretKey32Version, LweSecretKey64, LweSecretKey64Version,
    LweSeededCiphertext32, LweSeededCiphertext32Version, LweSeededCiphertext64,
    LweSeededCiphertext64Version, PackingKeyswitchKey32, PackingKeyswitchKey32Version,
    PackingKeyswitchKey64, PackingKeyswitchKey64Version, Plaintext32, Plaintext32Version,
    Plaintext64, Plaintext64Version, PlaintextVector32, PlaintextVector32Version,
    PlaintextVector64, PlaintextVector64Version,
};
use concrete_commons::key_kinds::BinaryKeyKind;
use serde::Serialize;

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 32 bits integers. It serializes a cleartext entity.
impl EntitySerializationEngine<Cleartext32, Vec<u8>> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let input: u32 = 3;
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let cleartext: Cleartext32 = engine.create_cleartext(&input)?;
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&cleartext)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(cleartext, recovered);
    /// engine.destroy(cleartext)?;
    /// engine.destroy(recovered)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn serialize(
        &mut self,
        entity: &Cleartext32,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableCleartext32<'a> {
            version: Cleartext32Version,
            inner: &'a ImplCleartext<u32>,
        }
        let serializable = SerializableCleartext32 {
            version: Cleartext32Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &Cleartext32) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 64 bits integers. It serializes a cleartext entity.
impl EntitySerializationEngine<Cleartext64, Vec<u8>> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let input: u64 = 3;
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let cleartext: Cleartext64 = engine.create_cleartext(&input)?;
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&cleartext)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(cleartext, recovered);
    /// engine.destroy(cleartext)?;
    /// engine.destroy(recovered)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn serialize(
        &mut self,
        entity: &Cleartext64,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableCleartext64<'a> {
            version: Cleartext64Version,
            inner: &'a ImplCleartext<u64>,
        }
        let serializable = SerializableCleartext64 {
            version: Cleartext64Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &Cleartext64) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 32 bits integers. It serializes a cleartext vector entity.
impl EntitySerializationEngine<CleartextVector32, Vec<u8>> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_commons::parameters::CleartextCount;
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let input = vec![3_u32; 100];
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let cleartext_vector: CleartextVector32 = engine.create_cleartext_vector(&input)?;
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&cleartext_vector)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(cleartext_vector, recovered);
    /// engine.destroy(cleartext_vector)?;
    /// engine.destroy(recovered)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn serialize(
        &mut self,
        entity: &CleartextVector32,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableCleartextVector32<'a> {
            version: CleartextVector32Version,
            inner: &'a ImplCleartextList<Vec<u32>>,
        }
        let serializable = SerializableCleartextVector32 {
            version: CleartextVector32Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &CleartextVector32) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 64 bits integers. It serializes a cleartext vector entity.
impl EntitySerializationEngine<CleartextVector64, Vec<u8>> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_commons::parameters::CleartextCount;
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let input = vec![3_u64; 100];
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let cleartext_vector: CleartextVector64 = engine.create_cleartext_vector(&input)?;
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&cleartext_vector)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(cleartext_vector, recovered);
    /// engine.destroy(cleartext_vector)?;
    /// engine.destroy(recovered)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn serialize(
        &mut self,
        entity: &CleartextVector64,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableCleartextVector64<'a> {
            version: CleartextVector64Version,
            inner: &'a ImplCleartextList<Vec<u64>>,
        }
        let serializable = SerializableCleartextVector64 {
            version: CleartextVector64Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &CleartextVector64) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 32 bits integers. It serializes a GGSW ciphertext entity.
impl EntitySerializationEngine<GgswCiphertext32, Vec<u8>> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize,
    /// };
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// let level = DecompositionLevelCount(1);
    /// let base_log = DecompositionBaseLog(4);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = 3_u32 << 20;
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: GlweSecretKey32 = engine.create_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext = engine.create_plaintext(&input)?;
    ///
    /// let ciphertext =
    ///     engine.encrypt_scalar_ggsw_ciphertext(&key, &plaintext, noise, level, base_log)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&ciphertext)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(ciphertext, recovered);
    ///
    /// engine.destroy(key)?;
    /// engine.destroy(plaintext)?;
    /// engine.destroy(ciphertext)?;
    /// engine.destroy(recovered)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn serialize(
        &mut self,
        entity: &GgswCiphertext32,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableGgswCiphertext32<'a> {
            version: GgswCiphertext32Version,
            inner: &'a ImplStandardGgswCiphertext<Vec<u32>>,
        }
        let serializable = SerializableGgswCiphertext32 {
            version: GgswCiphertext32Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &GgswCiphertext32) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 64 bits integers. It serializes a GGSW ciphertext entity.
impl EntitySerializationEngine<GgswCiphertext64, Vec<u8>> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize,
    /// };
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// let level = DecompositionLevelCount(1);
    /// let base_log = DecompositionBaseLog(4);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = 3_u64 << 50;
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: GlweSecretKey64 = engine.create_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext = engine.create_plaintext(&input)?;
    ///
    /// let ciphertext =
    ///     engine.encrypt_scalar_ggsw_ciphertext(&key, &plaintext, noise, level, base_log)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&ciphertext)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(ciphertext, recovered);
    ///
    /// engine.destroy(key)?;
    /// engine.destroy(plaintext)?;
    /// engine.destroy(ciphertext)?;
    /// engine.destroy(recovered)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn serialize(
        &mut self,
        entity: &GgswCiphertext64,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableGgswCiphertext64<'a> {
            version: GgswCiphertext64Version,
            inner: &'a ImplStandardGgswCiphertext<Vec<u64>>,
        }
        let serializable = SerializableGgswCiphertext64 {
            version: GgswCiphertext64Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &GgswCiphertext64) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 32 bits integers. It serializes a GLWE ciphertext entity.
impl EntitySerializationEngine<GlweCiphertext32, Vec<u8>> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{GlweDimension, PolynomialSize};
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // There are always polynomial_size messages encrypted in the GLWE ciphertext
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; polynomial_size.0];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: GlweSecretKey32 = engine.create_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_vector = engine.create_plaintext_vector(&input)?;
    ///
    /// let ciphertext = engine.encrypt_glwe_ciphertext(&key, &plaintext_vector, noise)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&ciphertext)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(ciphertext, recovered);
    ///
    /// engine.destroy(key)?;
    /// engine.destroy(plaintext_vector)?;
    /// engine.destroy(ciphertext)?;
    /// engine.destroy(recovered)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn serialize(
        &mut self,
        entity: &GlweCiphertext32,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableGlweCiphertext32<'a> {
            version: GlweCiphertext32Version,
            inner: &'a ImplGlweCiphertext<Vec<u32>>,
        }
        let serializable = SerializableGlweCiphertext32 {
            version: GlweCiphertext32Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &GlweCiphertext32) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 64 bits integers. It serializes a GLWE ciphertext entity.
impl EntitySerializationEngine<GlweCiphertext64, Vec<u8>> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{GlweDimension, PolynomialSize};
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // There are always polynomial_size messages encrypted in the GLWE ciphertext
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; polynomial_size.0];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: GlweSecretKey64 = engine.create_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_vector = engine.create_plaintext_vector(&input)?;
    ///
    /// let ciphertext = engine.encrypt_glwe_ciphertext(&key, &plaintext_vector, noise)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&ciphertext)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(ciphertext, recovered);
    ///
    /// engine.destroy(key)?;
    /// engine.destroy(plaintext_vector)?;
    /// engine.destroy(ciphertext)?;
    /// engine.destroy(recovered)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn serialize(
        &mut self,
        entity: &GlweCiphertext64,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableGlweCiphertext64<'a> {
            version: GlweCiphertext64Version,
            inner: &'a ImplGlweCiphertext<Vec<u64>>,
        }
        let serializable = SerializableGlweCiphertext64 {
            version: GlweCiphertext64Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &GlweCiphertext64) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 32 bits integers. It serializes a GLWE ciphertext view entity.
impl<'b> EntitySerializationEngine<GlweCiphertextView32<'b>, Vec<u8>>
    for DefaultSerializationEngine
{
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{GlweDimension, PolynomialSize};
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // There are always polynomial_size messages encrypted in the GLWE ciphertext
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; polynomial_size.0];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: GlweSecretKey32 = engine.create_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_vector = engine.create_plaintext_vector(&input)?;
    ///
    /// let ciphertext = engine.encrypt_glwe_ciphertext(&key, &plaintext_vector, noise)?;
    /// let raw_buffer = engine.consume_retrieve_glwe_ciphertext(ciphertext)?;
    /// let view: GlweCiphertextView32 =
    ///     engine.create_glwe_ciphertext(raw_buffer.as_slice(), polynomial_size)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&view)?;
    /// let recovered: GlweCiphertext32 = serialization_engine.deserialize(serialized.as_slice())?;
    /// let recovered_buffer = engine.consume_retrieve_glwe_ciphertext(recovered)?;
    /// assert_eq!(raw_buffer, recovered_buffer);
    ///
    /// engine.destroy(key)?;
    /// engine.destroy(plaintext_vector)?;
    /// engine.destroy(view)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn serialize(
        &mut self,
        entity: &GlweCiphertextView32<'b>,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableGlweCiphertextView32<'a, 'b> {
            version: GlweCiphertext32Version,
            inner: &'a ImplGlweCiphertext<&'b [u32]>,
        }
        let serializable = SerializableGlweCiphertextView32 {
            version: GlweCiphertext32Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &GlweCiphertextView32<'b>) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 64 bits integers. It serializes a GLWE ciphertext view entity.
impl<'b> EntitySerializationEngine<GlweCiphertextView64<'b>, Vec<u8>>
    for DefaultSerializationEngine
{
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{GlweDimension, PolynomialSize};
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // There are always polynomial_size messages encrypted in the GLWE ciphertext
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; polynomial_size.0];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: GlweSecretKey64 = engine.create_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_vector = engine.create_plaintext_vector(&input)?;
    /// let ciphertext = engine.encrypt_glwe_ciphertext(&key, &plaintext_vector, noise)?;
    ///
    /// let raw_buffer = engine.consume_retrieve_glwe_ciphertext(ciphertext)?;
    /// let view: GlweCiphertextView64 =
    ///     engine.create_glwe_ciphertext(raw_buffer.as_slice(), polynomial_size)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&view)?;
    /// let recovered: GlweCiphertext64 = serialization_engine.deserialize(serialized.as_slice())?;
    /// let recovered_buffer = engine.consume_retrieve_glwe_ciphertext(recovered)?;
    /// assert_eq!(raw_buffer, recovered_buffer);
    ///
    /// engine.destroy(key)?;
    /// engine.destroy(plaintext_vector)?;
    /// engine.destroy(view)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn serialize(
        &mut self,
        entity: &GlweCiphertextView64<'b>,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableGlweCiphertextView64<'a, 'b> {
            version: GlweCiphertext64Version,
            inner: &'a ImplGlweCiphertext<&'b [u64]>,
        }
        let serializable = SerializableGlweCiphertextView64 {
            version: GlweCiphertext64Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &GlweCiphertextView64<'b>) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 32 bits integers. It serializes a GLWE ciphertext mut view entity.
impl<'b> EntitySerializationEngine<GlweCiphertextMutView32<'b>, Vec<u8>>
    for DefaultSerializationEngine
{
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{GlweDimension, PolynomialSize};
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // There are always polynomial_size messages encrypted in the GLWE ciphertext
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; polynomial_size.0];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: GlweSecretKey32 = engine.create_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_vector = engine.create_plaintext_vector(&input)?;
    ///
    /// let ciphertext = engine.encrypt_glwe_ciphertext(&key, &plaintext_vector, noise)?;
    /// let mut raw_buffer = engine.consume_retrieve_glwe_ciphertext(ciphertext)?;
    /// let view: GlweCiphertextMutView32 =
    ///     engine.create_glwe_ciphertext(raw_buffer.as_mut_slice(), polynomial_size)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&view)?;
    /// engine.destroy(view)?;
    /// let recovered: GlweCiphertext32 = serialization_engine.deserialize(serialized.as_slice())?;
    /// let recovered_buffer = engine.consume_retrieve_glwe_ciphertext(recovered)?;
    /// assert_eq!(raw_buffer, recovered_buffer);
    ///
    /// engine.destroy(key)?;
    /// engine.destroy(plaintext_vector)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn serialize(
        &mut self,
        entity: &GlweCiphertextMutView32<'b>,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableGlweCiphertextMutView32<'a, 'b> {
            version: GlweCiphertext32Version,
            inner: &'a ImplGlweCiphertext<&'b mut [u32]>,
        }
        let serializable = SerializableGlweCiphertextMutView32 {
            version: GlweCiphertext32Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &GlweCiphertextMutView32<'b>) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 64 bits integers. It serializes a GLWE ciphertext mut view entity.
impl<'b> EntitySerializationEngine<GlweCiphertextMutView64<'b>, Vec<u8>>
    for DefaultSerializationEngine
{
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{GlweDimension, PolynomialSize};
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // There are always polynomial_size messages encrypted in the GLWE ciphertext
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; polynomial_size.0];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: GlweSecretKey64 = engine.create_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_vector = engine.create_plaintext_vector(&input)?;
    /// let ciphertext = engine.encrypt_glwe_ciphertext(&key, &plaintext_vector, noise)?;
    ///
    /// let mut raw_buffer = engine.consume_retrieve_glwe_ciphertext(ciphertext)?;
    /// let view: GlweCiphertextMutView64 =
    ///     engine.create_glwe_ciphertext(raw_buffer.as_mut_slice(), polynomial_size)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&view)?;
    /// engine.destroy(view)?;
    /// let recovered: GlweCiphertext64 = serialization_engine.deserialize(serialized.as_slice())?;
    /// let recovered_buffer = engine.consume_retrieve_glwe_ciphertext(recovered)?;
    /// assert_eq!(raw_buffer, recovered_buffer);
    ///
    /// engine.destroy(key)?;
    /// engine.destroy(plaintext_vector)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn serialize(
        &mut self,
        entity: &GlweCiphertextMutView64<'b>,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableGlweCiphertextMutView64<'a, 'b> {
            version: GlweCiphertext64Version,
            inner: &'a ImplGlweCiphertext<&'b mut [u64]>,
        }
        let serializable = SerializableGlweCiphertextMutView64 {
            version: GlweCiphertext64Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &GlweCiphertextMutView64<'b>) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 32 bits integers. It serializes a GLWE ciphertext vector entity.
impl EntitySerializationEngine<GlweCiphertextVector32, Vec<u8>> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{GlweCiphertextCount, GlweDimension, PolynomialSize};
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; 8];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: GlweSecretKey32 = engine.create_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_vector = engine.create_plaintext_vector(&input)?;
    ///
    /// let ciphertext_vector =
    ///     engine.encrypt_glwe_ciphertext_vector(&key, &plaintext_vector, noise)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&ciphertext_vector)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(ciphertext_vector, recovered);
    ///
    /// engine.destroy(ciphertext_vector)?;
    /// engine.destroy(plaintext_vector)?;
    /// engine.destroy(key)?;
    /// engine.destroy(recovered)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn serialize(
        &mut self,
        entity: &GlweCiphertextVector32,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableGlweCiphertextVector32<'a> {
            version: GlweCiphertextVector32Version,
            inner: &'a ImplGlweList<Vec<u32>>,
        }
        let serializable = SerializableGlweCiphertextVector32 {
            version: GlweCiphertextVector32Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &GlweCiphertextVector32) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 64 bits integers. It serializes a GLWE ciphertext vector entity.
impl EntitySerializationEngine<GlweCiphertextVector64, Vec<u8>> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{GlweCiphertextCount, GlweDimension, PolynomialSize};
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; 8];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: GlweSecretKey64 = engine.create_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_vector = engine.create_plaintext_vector(&input)?;
    ///
    /// let ciphertext_vector =
    ///     engine.encrypt_glwe_ciphertext_vector(&key, &plaintext_vector, noise)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&ciphertext_vector)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(ciphertext_vector, recovered);
    ///
    /// engine.destroy(ciphertext_vector)?;
    /// engine.destroy(plaintext_vector)?;
    /// engine.destroy(key)?;
    /// engine.destroy(recovered)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn serialize(
        &mut self,
        entity: &GlweCiphertextVector64,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableGlweCiphertextVector64<'a> {
            version: GlweCiphertextVector64Version,
            inner: &'a ImplGlweList<Vec<u64>>,
        }
        let serializable = SerializableGlweCiphertextVector64 {
            version: GlweCiphertextVector64Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &GlweCiphertextVector64) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 32 bits integers. It serializes a GLWE secret key entity.
impl EntitySerializationEngine<GlweSecretKey32, Vec<u8>> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_commons::parameters::{GlweDimension, PolynomialSize};
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let glwe_secret_key: GlweSecretKey32 =
    ///     engine.create_glwe_secret_key(glwe_dimension, polynomial_size)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&glwe_secret_key)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(glwe_secret_key, recovered);
    ///
    /// engine.destroy(glwe_secret_key)?;
    /// engine.destroy(recovered)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn serialize(
        &mut self,
        entity: &GlweSecretKey32,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableGlweSecretKey32<'a> {
            version: GlweSecretKey32Version,
            inner: &'a ImplGlweSecretKey<BinaryKeyKind, Vec<u32>>,
        }
        let serializable = SerializableGlweSecretKey32 {
            version: GlweSecretKey32Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &GlweSecretKey32) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 64 bits integers. It serializes a GLWE secret key entity.
impl EntitySerializationEngine<GlweSecretKey64, Vec<u8>> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_commons::parameters::{GlweDimension, PolynomialSize};
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let glwe_secret_key: GlweSecretKey64 =
    ///     engine.create_glwe_secret_key(glwe_dimension, polynomial_size)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&glwe_secret_key)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(glwe_secret_key, recovered);
    ///
    /// engine.destroy(glwe_secret_key)?;
    /// engine.destroy(recovered)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn serialize(
        &mut self,
        entity: &GlweSecretKey64,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableGlweSecretKey64<'a> {
            version: GlweSecretKey64Version,
            inner: &'a ImplGlweSecretKey<BinaryKeyKind, Vec<u64>>,
        }
        let serializable = SerializableGlweSecretKey64 {
            version: GlweSecretKey64Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &GlweSecretKey64) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 32 bits integers. It serializes a LWE bootstrap key entity.
impl EntitySerializationEngine<LweBootstrapKey32, Vec<u8>> for DefaultSerializationEngine {
    /// # Example
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    /// };
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let (lwe_dim, glwe_dim, poly_size) = (LweDimension(4), GlweDimension(6), PolynomialSize(256));
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(5));
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let lwe_sk: LweSecretKey32 = engine.create_lwe_secret_key(lwe_dim)?;
    /// let glwe_sk: GlweSecretKey32 = engine.create_glwe_secret_key(glwe_dim, poly_size)?;
    ///
    /// let bsk: LweBootstrapKey32 =
    ///     engine.create_lwe_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&bsk)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(bsk, recovered);
    ///
    /// engine.destroy(lwe_sk)?;
    /// engine.destroy(glwe_sk)?;
    /// engine.destroy(bsk)?;
    /// engine.destroy(recovered)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn serialize(
        &mut self,
        entity: &LweBootstrapKey32,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableLweBootstrapKey32<'a> {
            version: LweBootstrapKey32Version,
            inner: &'a ImplStandardBootstrapKey<Vec<u32>>,
        }
        let serializable = SerializableLweBootstrapKey32 {
            version: LweBootstrapKey32Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &LweBootstrapKey32) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 64 bits integers. It serializes a LWE bootstrap key entity.
impl EntitySerializationEngine<LweBootstrapKey64, Vec<u8>> for DefaultSerializationEngine {
    /// # Example
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    /// };
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let (lwe_dim, glwe_dim, poly_size) = (LweDimension(4), GlweDimension(6), PolynomialSize(256));
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(5));
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let lwe_sk: LweSecretKey64 = engine.create_lwe_secret_key(lwe_dim)?;
    /// let glwe_sk: GlweSecretKey64 = engine.create_glwe_secret_key(glwe_dim, poly_size)?;
    ///
    /// let bsk: LweBootstrapKey64 =
    ///     engine.create_lwe_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&bsk)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(bsk, recovered);
    ///
    /// engine.destroy(lwe_sk)?;
    /// engine.destroy(glwe_sk)?;
    /// engine.destroy(bsk)?;
    /// engine.destroy(recovered)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn serialize(
        &mut self,
        entity: &LweBootstrapKey64,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableLweBootstrapKey64<'a> {
            version: LweBootstrapKey64Version,
            inner: &'a ImplStandardBootstrapKey<Vec<u64>>,
        }
        let serializable = SerializableLweBootstrapKey64 {
            version: LweBootstrapKey64Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &LweBootstrapKey64) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 32 bits integers. It serializes a LWE ciphertext entity.
impl EntitySerializationEngine<LweCiphertext32, Vec<u8>> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::LweDimension;
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(2);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = 3_u32 << 20;
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey32 = engine.create_lwe_secret_key(lwe_dimension)?;
    /// let plaintext = engine.create_plaintext(&input)?;
    ///
    /// let ciphertext = engine.encrypt_lwe_ciphertext(&key, &plaintext, noise)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&ciphertext)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(ciphertext, recovered);
    ///
    /// engine.destroy(key)?;
    /// engine.destroy(plaintext)?;
    /// engine.destroy(ciphertext)?;
    /// engine.destroy(recovered)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn serialize(
        &mut self,
        entity: &LweCiphertext32,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableLweCiphertext32<'a> {
            version: LweCiphertext32Version,
            inner: &'a ImplLweCiphertext<Vec<u32>>,
        }
        let serializable = SerializableLweCiphertext32 {
            version: LweCiphertext32Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &LweCiphertext32) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 64 bits integers. It serializes a LWE ciphertext entity.
impl EntitySerializationEngine<LweCiphertext64, Vec<u8>> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::LweDimension;
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(2);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = 3_u64 << 50;
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey64 = engine.create_lwe_secret_key(lwe_dimension)?;
    /// let plaintext = engine.create_plaintext(&input)?;
    ///
    /// let ciphertext = engine.encrypt_lwe_ciphertext(&key, &plaintext, noise)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&ciphertext)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(ciphertext, recovered);
    ///
    /// engine.destroy(key)?;
    /// engine.destroy(plaintext)?;
    /// engine.destroy(ciphertext)?;
    /// engine.destroy(recovered)?;
    /// #
    /// # Ok(())
    /// # }
    fn serialize(
        &mut self,
        entity: &LweCiphertext64,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableLweCiphertext64<'a> {
            version: LweCiphertext64Version,
            inner: &'a ImplLweCiphertext<Vec<u64>>,
        }
        let serializable = SerializableLweCiphertext64 {
            version: LweCiphertext64Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &LweCiphertext64) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 32 bits integers. It serializes a LWE ciphertext view entity.
impl<'b> EntitySerializationEngine<LweCiphertextView32<'b>, Vec<u8>>
    for DefaultSerializationEngine
{
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::LweDimension;
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(2);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = 3_u32 << 20;
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey32 = engine.create_lwe_secret_key(lwe_dimension)?;
    /// let plaintext = engine.create_plaintext(&input)?;
    ///
    /// let ciphertext = engine.encrypt_lwe_ciphertext(&key, &plaintext, noise)?;
    /// let raw_buffer = engine.consume_retrieve_lwe_ciphertext(ciphertext)?;
    /// let view: LweCiphertextView32 = engine.create_lwe_ciphertext(raw_buffer.as_slice())?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&view)?;
    /// let recovered: LweCiphertext32 = serialization_engine.deserialize(serialized.as_slice())?;
    /// let recovered_buffer = engine.consume_retrieve_lwe_ciphertext(recovered)?;
    /// assert_eq!(raw_buffer, recovered_buffer);
    ///
    /// engine.destroy(key)?;
    /// engine.destroy(plaintext)?;
    /// engine.destroy(view)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn serialize(
        &mut self,
        entity: &LweCiphertextView32<'b>,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableLweCiphertextView32<'a, 'b> {
            version: LweCiphertext32Version,
            inner: &'a ImplLweCiphertext<&'b [u32]>,
        }
        let serializable = SerializableLweCiphertextView32 {
            version: LweCiphertext32Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &LweCiphertextView32<'b>) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 64 bits integers. It serializes a LWE ciphertext view entity.
impl<'b> EntitySerializationEngine<LweCiphertextView64<'b>, Vec<u8>>
    for DefaultSerializationEngine
{
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::LweDimension;
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(2);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = 3_u64 << 50;
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey64 = engine.create_lwe_secret_key(lwe_dimension)?;
    /// let plaintext = engine.create_plaintext(&input)?;
    ///
    /// let ciphertext = engine.encrypt_lwe_ciphertext(&key, &plaintext, noise)?;
    ///
    /// let raw_buffer = engine.consume_retrieve_lwe_ciphertext(ciphertext)?;
    /// let view: LweCiphertextView64 = engine.create_lwe_ciphertext(raw_buffer.as_slice())?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&view)?;
    /// let recovered: LweCiphertext64 = serialization_engine.deserialize(serialized.as_slice())?;
    /// let recovered_buffer = engine.consume_retrieve_lwe_ciphertext(recovered)?;
    /// assert_eq!(raw_buffer, recovered_buffer);
    ///
    /// engine.destroy(key)?;
    /// engine.destroy(plaintext)?;
    /// engine.destroy(view)?;
    /// #
    /// # Ok(())
    /// # }
    fn serialize(
        &mut self,
        entity: &LweCiphertextView64<'b>,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableLweCiphertextView64<'a, 'b> {
            version: LweCiphertext64Version,
            inner: &'a ImplLweCiphertext<&'b [u64]>,
        }
        let serializable = SerializableLweCiphertextView64 {
            version: LweCiphertext64Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &LweCiphertextView64<'b>) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 32 bits integers. It serializes a LWE ciphertext mut view entity.
impl<'b> EntitySerializationEngine<LweCiphertextMutView32<'b>, Vec<u8>>
    for DefaultSerializationEngine
{
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::LweDimension;
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(2);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = 3_u32 << 20;
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey32 = engine.create_lwe_secret_key(lwe_dimension)?;
    /// let plaintext = engine.create_plaintext(&input)?;
    ///
    /// let ciphertext = engine.encrypt_lwe_ciphertext(&key, &plaintext, noise)?;
    /// let mut raw_buffer = engine.consume_retrieve_lwe_ciphertext(ciphertext)?;
    /// let view: LweCiphertextMutView32 = engine.create_lwe_ciphertext(raw_buffer.as_mut_slice())?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&view)?;
    /// engine.destroy(view)?;
    /// let recovered: LweCiphertext32 = serialization_engine.deserialize(serialized.as_slice())?;
    /// let recovered_buffer = engine.consume_retrieve_lwe_ciphertext(recovered)?;
    /// assert_eq!(raw_buffer, recovered_buffer);
    ///
    /// engine.destroy(key)?;
    /// engine.destroy(plaintext)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn serialize(
        &mut self,
        entity: &LweCiphertextMutView32<'b>,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableLweCiphertextMutView32<'a, 'b> {
            version: LweCiphertext32Version,
            inner: &'a ImplLweCiphertext<&'b mut [u32]>,
        }
        let serializable = SerializableLweCiphertextMutView32 {
            version: LweCiphertext32Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &LweCiphertextMutView32<'b>) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 64 bits integers. It serializes a LWE ciphertext mut view entity.
impl<'b> EntitySerializationEngine<LweCiphertextMutView64<'b>, Vec<u8>>
    for DefaultSerializationEngine
{
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::LweDimension;
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(2);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = 3_u64 << 50;
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey64 = engine.create_lwe_secret_key(lwe_dimension)?;
    /// let plaintext = engine.create_plaintext(&input)?;
    ///
    /// let ciphertext = engine.encrypt_lwe_ciphertext(&key, &plaintext, noise)?;
    ///
    /// let mut raw_buffer = engine.consume_retrieve_lwe_ciphertext(ciphertext)?;
    /// let view: LweCiphertextMutView64 = engine.create_lwe_ciphertext(raw_buffer.as_mut_slice())?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&view)?;
    /// engine.destroy(view)?;
    /// let recovered: LweCiphertext64 = serialization_engine.deserialize(serialized.as_slice())?;
    /// let recovered_buffer = engine.consume_retrieve_lwe_ciphertext(recovered)?;
    /// assert_eq!(raw_buffer, recovered_buffer);
    ///
    /// engine.destroy(key)?;
    /// engine.destroy(plaintext)?;
    /// #
    /// # Ok(())
    /// # }
    fn serialize(
        &mut self,
        entity: &LweCiphertextMutView64<'b>,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableLweCiphertextMutView64<'a, 'b> {
            version: LweCiphertext64Version,
            inner: &'a ImplLweCiphertext<&'b mut [u64]>,
        }
        let serializable = SerializableLweCiphertextMutView64 {
            version: LweCiphertext64Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &LweCiphertextMutView64<'b>) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 32 bits integers. It serializes a LWE ciphertext vector entity.
impl EntitySerializationEngine<LweCiphertextVector32, Vec<u8>> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{LweCiphertextCount, LweDimension};
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; 3];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey32 = engine.create_lwe_secret_key(lwe_dimension)?;
    /// let plaintext_vector: PlaintextVector32 = engine.create_plaintext_vector(&input)?;
    ///
    /// let mut ciphertext_vector: LweCiphertextVector32 =
    ///     engine.encrypt_lwe_ciphertext_vector(&key, &plaintext_vector, noise)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&ciphertext_vector)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(ciphertext_vector, recovered);
    ///
    /// engine.destroy(key)?;
    /// engine.destroy(plaintext_vector)?;
    /// engine.destroy(ciphertext_vector)?;
    /// engine.destroy(recovered)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn serialize(
        &mut self,
        entity: &LweCiphertextVector32,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableLweCiphertextVector32<'a> {
            version: LweCiphertextVector32Version,
            inner: &'a ImplLweList<Vec<u32>>,
        }
        let serializable = SerializableLweCiphertextVector32 {
            version: LweCiphertextVector32Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &LweCiphertextVector32) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 64 bits integers. It serializes a LWE ciphertext vector entity.
impl EntitySerializationEngine<LweCiphertextVector64, Vec<u8>> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{LweCiphertextCount, LweDimension};
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; 3];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey64 = engine.create_lwe_secret_key(lwe_dimension)?;
    /// let plaintext_vector: PlaintextVector64 = engine.create_plaintext_vector(&input)?;
    ///
    /// let mut ciphertext_vector: LweCiphertextVector64 =
    ///     engine.encrypt_lwe_ciphertext_vector(&key, &plaintext_vector, noise)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&ciphertext_vector)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(ciphertext_vector, recovered);
    ///
    /// engine.destroy(key)?;
    /// engine.destroy(plaintext_vector)?;
    /// engine.destroy(ciphertext_vector)?;
    /// engine.destroy(recovered)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn serialize(
        &mut self,
        entity: &LweCiphertextVector64,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableLweCiphertextVector64<'a> {
            version: LweCiphertextVector64Version,
            inner: &'a ImplLweList<Vec<u64>>,
        }
        let serializable = SerializableLweCiphertextVector64 {
            version: LweCiphertextVector64Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &LweCiphertextVector64) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 32 bits integers. It serializes a LWE keyswitch key entity.
impl EntitySerializationEngine<LweKeyswitchKey32, Vec<u8>> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, LweDimension,
    /// };
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let input_lwe_dimension = LweDimension(6);
    /// let output_lwe_dimension = LweDimension(3);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// let decomposition_base_log = DecompositionBaseLog(8);
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let input_key: LweSecretKey32 = engine.create_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: LweSecretKey32 = engine.create_lwe_secret_key(output_lwe_dimension)?;
    ///
    /// let keyswitch_key = engine.create_lwe_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     decomposition_level_count,
    ///     decomposition_base_log,
    ///     noise,
    /// )?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&keyswitch_key)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(keyswitch_key, recovered);
    ///
    /// engine.destroy(input_key)?;
    /// engine.destroy(output_key)?;
    /// engine.destroy(keyswitch_key)?;
    /// engine.destroy(recovered)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn serialize(
        &mut self,
        entity: &LweKeyswitchKey32,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableLweKeyswitchKey32<'a> {
            version: LweKeyswitchKey32Version,
            inner: &'a ImplLweKeyswitchKey<Vec<u32>>,
        }
        let serializable = SerializableLweKeyswitchKey32 {
            version: LweKeyswitchKey32Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &LweKeyswitchKey32) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 64 bits integers. It serializes a LWE keyswitch key entity.
impl EntitySerializationEngine<LweKeyswitchKey64, Vec<u8>> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, LweDimension,
    /// };
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let input_lwe_dimension = LweDimension(6);
    /// let output_lwe_dimension = LweDimension(3);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// let decomposition_base_log = DecompositionBaseLog(8);
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let input_key: LweSecretKey64 = engine.create_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: LweSecretKey64 = engine.create_lwe_secret_key(output_lwe_dimension)?;
    ///
    /// let keyswitch_key = engine.create_lwe_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     decomposition_level_count,
    ///     decomposition_base_log,
    ///     noise,
    /// )?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&keyswitch_key)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(keyswitch_key, recovered);
    ///
    /// engine.destroy(input_key)?;
    /// engine.destroy(output_key)?;
    /// engine.destroy(keyswitch_key)?;
    /// engine.destroy(recovered)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn serialize(
        &mut self,
        entity: &LweKeyswitchKey64,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableLweKeyswitchKey64<'a> {
            version: LweKeyswitchKey64Version,
            inner: &'a ImplLweKeyswitchKey<Vec<u64>>,
        }
        let serializable = SerializableLweKeyswitchKey64 {
            version: LweKeyswitchKey64Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &LweKeyswitchKey64) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 32 bits integers. It serializes a LWE secret key entity.
impl EntitySerializationEngine<LweSecretKey32, Vec<u8>> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_commons::parameters::LweDimension;
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let lwe_secret_key: LweSecretKey32 = engine.create_lwe_secret_key(lwe_dimension)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&lwe_secret_key)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(lwe_secret_key, recovered);
    ///
    /// engine.destroy(lwe_secret_key)?;
    /// engine.destroy(recovered)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn serialize(
        &mut self,
        entity: &LweSecretKey32,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableLweSecretKey32<'a> {
            version: LweSecretKey32Version,
            inner: &'a ImplLweSecretKey<BinaryKeyKind, Vec<u32>>,
        }
        let serializable = SerializableLweSecretKey32 {
            version: LweSecretKey32Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &LweSecretKey32) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 64 bits integers. It serializes a LWE secret key entity.
impl EntitySerializationEngine<LweSecretKey64, Vec<u8>> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_commons::parameters::LweDimension;
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let lwe_secret_key: LweSecretKey64 = engine.create_lwe_secret_key(lwe_dimension)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&lwe_secret_key)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(lwe_secret_key, recovered);
    ///
    /// engine.destroy(lwe_secret_key)?;
    /// engine.destroy(recovered)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn serialize(
        &mut self,
        entity: &LweSecretKey64,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableLweSecretKey64<'a> {
            version: LweSecretKey64Version,
            inner: &'a ImplLweSecretKey<BinaryKeyKind, Vec<u64>>,
        }
        let serializable = SerializableLweSecretKey64 {
            version: LweSecretKey64Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &LweSecretKey64) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 32 bits integers. It serializes a seeded LWE ciphertext entity.
impl EntitySerializationEngine<LweSeededCiphertext32, Vec<u8>> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::LweDimension;
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(2);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = 3_u32 << 20;
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey32 = engine.create_lwe_secret_key(lwe_dimension)?;
    /// let plaintext = engine.create_plaintext(&input)?;
    ///
    /// let ciphertext: LweSeededCiphertext32 =
    ///     engine.encrypt_lwe_seeded_ciphertext(&key, &plaintext, noise)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&ciphertext)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(ciphertext, recovered);
    ///
    /// engine.destroy(key)?;
    /// engine.destroy(plaintext)?;
    /// engine.destroy(ciphertext)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn serialize(
        &mut self,
        entity: &LweSeededCiphertext32,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableLweSeededCiphertext32<'a> {
            version: LweSeededCiphertext32Version,
            inner: &'a ImplLweSeededCiphertext<u32>,
        }
        let serializable = SerializableLweSeededCiphertext32 {
            version: LweSeededCiphertext32Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &LweSeededCiphertext32) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 64 bits integers. It serializes a seeded LWE ciphertext entity.
impl EntitySerializationEngine<LweSeededCiphertext64, Vec<u8>> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::LweDimension;
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(2);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = 3_u64 << 50;
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey64 = engine.create_lwe_secret_key(lwe_dimension)?;
    /// let plaintext = engine.create_plaintext(&input)?;
    ///
    /// let ciphertext: LweSeededCiphertext64 =
    ///     engine.encrypt_lwe_seeded_ciphertext(&key, &plaintext, noise)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&ciphertext)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(ciphertext, recovered);
    ///
    /// engine.destroy(key)?;
    /// engine.destroy(plaintext)?;
    /// engine.destroy(ciphertext)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn serialize(
        &mut self,
        entity: &LweSeededCiphertext64,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableLweSeededCiphertext64<'a> {
            version: LweSeededCiphertext64Version,
            inner: &'a ImplLweSeededCiphertext<u64>,
        }
        let serializable = SerializableLweSeededCiphertext64 {
            version: LweSeededCiphertext64Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &LweSeededCiphertext64) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 32 bits integers. It serializes a packing keyswitch key entity.
impl EntitySerializationEngine<PackingKeyswitchKey32, Vec<u8>> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, LweDimension,
    /// };
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let input_lwe_dimension = LweDimension(6);
    /// let output_lwe_dimension = LweDimension(3);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// let decomposition_base_log = DecompositionBaseLog(8);
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let input_key: LweSecretKey32 = engine.create_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: LweSecretKey32 = engine.create_lwe_secret_key(output_lwe_dimension)?;
    ///
    /// let packing_keyswitch_key = engine.create_lwe_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     decomposition_level_count,
    ///     decomposition_base_log,
    ///     noise,
    /// )?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&packing_keyswitch_key)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(packing_keyswitch_key, recovered);
    ///
    /// engine.destroy(input_key)?;
    /// engine.destroy(output_key)?;
    /// engine.destroy(packing_keyswitch_key)?;
    /// engine.destroy(recovered)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn serialize(
        &mut self,
        entity: &PackingKeyswitchKey32,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializablePackingKeyswitchKey32<'a> {
            version: PackingKeyswitchKey32Version,
            inner: &'a ImplPackingKeyswitchKey<Vec<u32>>,
        }
        let serializable = SerializablePackingKeyswitchKey32 {
            version: PackingKeyswitchKey32Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &PackingKeyswitchKey32) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 64 bits integers. It serializes a packing keyswitch key entity.
impl EntitySerializationEngine<PackingKeyswitchKey64, Vec<u8>> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, LweDimension,
    /// };
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let input_lwe_dimension = LweDimension(6);
    /// let output_lwe_dimension = LweDimension(3);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// let decomposition_base_log = DecompositionBaseLog(8);
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let input_key: LweSecretKey64 = engine.create_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: LweSecretKey64 = engine.create_lwe_secret_key(output_lwe_dimension)?;
    ///
    /// let packing_keyswitch_key = engine.create_lwe_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     decomposition_level_count,
    ///     decomposition_base_log,
    ///     noise,
    /// )?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&packing_keyswitch_key)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(packing_keyswitch_key, recovered);
    ///
    /// engine.destroy(input_key)?;
    /// engine.destroy(output_key)?;
    /// engine.destroy(packing_keyswitch_key)?;
    /// engine.destroy(recovered)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn serialize(
        &mut self,
        entity: &PackingKeyswitchKey64,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializablePackingKeyswitchKey64<'a> {
            version: PackingKeyswitchKey64Version,
            inner: &'a ImplPackingKeyswitchKey<Vec<u64>>,
        }
        let serializable = SerializablePackingKeyswitchKey64 {
            version: PackingKeyswitchKey64Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &PackingKeyswitchKey64) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 32 bits integers. It serializes a plaintext entity.
impl EntitySerializationEngine<Plaintext32, Vec<u8>> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = 3_u32 << 20;
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let plaintext: Plaintext32 = engine.create_plaintext(&input)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&plaintext)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(plaintext, recovered);
    ///
    /// engine.destroy(plaintext)?;
    /// engine.destroy(recovered)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn serialize(
        &mut self,
        entity: &Plaintext32,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializablePlaintext32<'a> {
            version: Plaintext32Version,
            inner: &'a ImplPlaintext<u32>,
        }
        let serializable = SerializablePlaintext32 {
            version: Plaintext32Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &Plaintext32) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 64 bits integers. It serializes a plaintext entity.
impl EntitySerializationEngine<Plaintext64, Vec<u8>> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = 3_u64 << 50;
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let plaintext: Plaintext64 = engine.create_plaintext(&input)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&plaintext)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(plaintext, recovered);
    /// engine.destroy(plaintext)?;
    /// engine.destroy(recovered)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn serialize(
        &mut self,
        entity: &Plaintext64,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializablePlaintext64<'a> {
            version: Plaintext64Version,
            inner: &'a ImplPlaintext<u64>,
        }
        let serializable = SerializablePlaintext64 {
            version: Plaintext64Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &Plaintext64) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 32 bits integers. It serializes a plaintext vector entity.
impl EntitySerializationEngine<PlaintextVector32, Vec<u8>> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_commons::parameters::PlaintextCount;
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; 3];
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let plaintext_vector: PlaintextVector32 = engine.create_plaintext_vector(&input)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&plaintext_vector)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(plaintext_vector, recovered);
    ///
    /// engine.destroy(plaintext_vector)?;
    /// engine.destroy(recovered)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn serialize(
        &mut self,
        entity: &PlaintextVector32,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializablePlaintextVector32<'a> {
            version: PlaintextVector32Version,
            inner: &'a ImplPlaintextList<Vec<u32>>,
        }
        let serializable = SerializablePlaintextVector32 {
            version: PlaintextVector32Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &PlaintextVector32) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 64 bits integers. It serializes a plaintext vector entity.
impl EntitySerializationEngine<PlaintextVector64, Vec<u8>> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_commons::parameters::PlaintextCount;
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; 3];
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let plaintext_vector: PlaintextVector64 = engine.create_plaintext_vector(&input)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&plaintext_vector)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(plaintext_vector, recovered);
    ///
    /// engine.destroy(plaintext_vector)?;
    /// engine.destroy(recovered)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn serialize(
        &mut self,
        entity: &PlaintextVector64,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializablePlaintextVector64<'a> {
            version: PlaintextVector64Version,
            inner: &'a ImplPlaintextList<Vec<u64>>,
        }
        let serializable = SerializablePlaintextVector64 {
            version: PlaintextVector64Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &PlaintextVector64) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}
