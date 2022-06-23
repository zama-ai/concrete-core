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
    DefaultSerializationEngine, DefaultSerializationError, EntityDeserializationEngine,
    EntityDeserializationError, GgswCiphertext32, GgswCiphertext32Version, GgswCiphertext64,
    GgswCiphertext64Version, GlweCiphertext32, GlweCiphertext32Version, GlweCiphertext64,
    GlweCiphertext64Version, GlweCiphertextVector32, GlweCiphertextVector32Version,
    GlweCiphertextVector64, GlweCiphertextVector64Version, GlweSecretKey32, GlweSecretKey32Version,
    GlweSecretKey64, GlweSecretKey64Version, LweBootstrapKey32, LweBootstrapKey32Version,
    LweBootstrapKey64, LweBootstrapKey64Version, LweCiphertext32, LweCiphertext32Version,
    LweCiphertext64, LweCiphertext64Version, LweCiphertextVector32, LweCiphertextVector32Version,
    LweCiphertextVector64, LweCiphertextVector64Version, LweKeyswitchKey32,
    LweKeyswitchKey32Version, LweKeyswitchKey64, LweKeyswitchKey64Version, LweSecretKey32,
    LweSecretKey32Version, LweSecretKey64, LweSecretKey64Version, LweSeededCiphertext32,
    LweSeededCiphertext32Version, LweSeededCiphertext64, LweSeededCiphertext64Version,
    PackingKeyswitchKey32, PackingKeyswitchKey32Version, PackingKeyswitchKey64,
    PackingKeyswitchKey64Version, Plaintext32, Plaintext32Version, Plaintext64, Plaintext64Version,
    PlaintextVector32, PlaintextVector32Version, PlaintextVector64, PlaintextVector64Version,
};
use concrete_commons::key_kinds::BinaryKeyKind;
use serde::Deserialize;

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 32 bits integers. It deserializes a cleartext entity.
impl EntityDeserializationEngine<&[u8], Cleartext32> for DefaultSerializationEngine {
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
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<Cleartext32, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableCleartext32 {
            version: Cleartext32Version,
            inner: ImplCleartext<u32>,
        }
        let deserialized: DeserializableCleartext32 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableCleartext32 {
                version: Cleartext32Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableCleartext32 {
                version: Cleartext32Version::V0,
                inner,
            } => Ok(Cleartext32(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> Cleartext32 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 64 bits integers. It deserializes a cleartext entity.
impl EntityDeserializationEngine<&[u8], Cleartext64> for DefaultSerializationEngine {
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
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<Cleartext64, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableCleartext64 {
            version: Cleartext64Version,
            inner: ImplCleartext<u64>,
        }
        let deserialized: DeserializableCleartext64 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableCleartext64 {
                version: Cleartext64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableCleartext64 {
                version: Cleartext64Version::V0,
                inner,
            } => Ok(Cleartext64(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> Cleartext64 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 32 bits integers. It deserializes a cleartext vector entity.
impl EntityDeserializationEngine<&[u8], CleartextVector32> for DefaultSerializationEngine {
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
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<CleartextVector32, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableCleartextVector32 {
            version: CleartextVector32Version,
            inner: ImplCleartextList<Vec<u32>>,
        }
        let deserialized: DeserializableCleartextVector32 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableCleartextVector32 {
                version: CleartextVector32Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableCleartextVector32 {
                version: CleartextVector32Version::V0,
                inner,
            } => Ok(CleartextVector32(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> CleartextVector32 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 64 bits integers. It deserializes a cleartext vector entity.
impl EntityDeserializationEngine<&[u8], CleartextVector64> for DefaultSerializationEngine {
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
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<CleartextVector64, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableCleartextVector64 {
            version: CleartextVector64Version,
            inner: ImplCleartextList<Vec<u64>>,
        }
        let deserialized: DeserializableCleartextVector64 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableCleartextVector64 {
                version: CleartextVector64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableCleartextVector64 {
                version: CleartextVector64Version::V0,
                inner,
            } => Ok(CleartextVector64(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> CleartextVector64 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 32 bits integers. It deserializes a GGSW ciphertext entity.
impl EntityDeserializationEngine<&[u8], GgswCiphertext32> for DefaultSerializationEngine {
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
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<GgswCiphertext32, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableGgswCiphertext32 {
            version: GgswCiphertext32Version,
            inner: ImplStandardGgswCiphertext<Vec<u32>>,
        }
        let deserialized: DeserializableGgswCiphertext32 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableGgswCiphertext32 {
                version: GgswCiphertext32Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableGgswCiphertext32 {
                version: GgswCiphertext32Version::V0,
                inner,
            } => Ok(GgswCiphertext32(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> GgswCiphertext32 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 64 bits integers. It deserializes a GGSW ciphertext entity.
impl EntityDeserializationEngine<&[u8], GgswCiphertext64> for DefaultSerializationEngine {
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
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<GgswCiphertext64, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableGgswCiphertext64 {
            version: GgswCiphertext64Version,
            inner: ImplStandardGgswCiphertext<Vec<u64>>,
        }
        let deserialized: DeserializableGgswCiphertext64 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableGgswCiphertext64 {
                version: GgswCiphertext64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableGgswCiphertext64 {
                version: GgswCiphertext64Version::V0,
                inner,
            } => Ok(GgswCiphertext64(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> GgswCiphertext64 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 32 bits integers. It deserializes a GLWE ciphertext entity.
impl EntityDeserializationEngine<&[u8], GlweCiphertext32> for DefaultSerializationEngine {
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
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<GlweCiphertext32, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableGlweCiphertext32 {
            version: GlweCiphertext32Version,
            inner: ImplGlweCiphertext<Vec<u32>>,
        }
        let deserialized: DeserializableGlweCiphertext32 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableGlweCiphertext32 {
                version: GlweCiphertext32Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableGlweCiphertext32 {
                version: GlweCiphertext32Version::V0,
                inner,
            } => Ok(GlweCiphertext32(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> GlweCiphertext32 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 64 bits integers. It deserializes a GLWE ciphertext entity.
impl EntityDeserializationEngine<&[u8], GlweCiphertext64> for DefaultSerializationEngine {
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
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<GlweCiphertext64, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableGlweCiphertext64 {
            version: GlweCiphertext64Version,
            inner: ImplGlweCiphertext<Vec<u64>>,
        }
        let deserialized: DeserializableGlweCiphertext64 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableGlweCiphertext64 {
                version: GlweCiphertext64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableGlweCiphertext64 {
                version: GlweCiphertext64Version::V0,
                inner,
            } => Ok(GlweCiphertext64(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> GlweCiphertext64 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 32 bits integers. It deserializes a GLWE ciphertext vector entity.
impl EntityDeserializationEngine<&[u8], GlweCiphertextVector32> for DefaultSerializationEngine {
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
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<GlweCiphertextVector32, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableGlweCiphertextVector32 {
            version: GlweCiphertextVector32Version,
            inner: ImplGlweList<Vec<u32>>,
        }
        let deserialized: DeserializableGlweCiphertextVector32 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableGlweCiphertextVector32 {
                version: GlweCiphertextVector32Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableGlweCiphertextVector32 {
                version: GlweCiphertextVector32Version::V0,
                inner,
            } => Ok(GlweCiphertextVector32(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> GlweCiphertextVector32 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 64 bits integers. It deserializes a GLWE ciphertext vector entity.
impl EntityDeserializationEngine<&[u8], GlweCiphertextVector64> for DefaultSerializationEngine {
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
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<GlweCiphertextVector64, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableGlweCiphertextVector64 {
            version: GlweCiphertextVector64Version,
            inner: ImplGlweList<Vec<u64>>,
        }
        let deserialized: DeserializableGlweCiphertextVector64 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableGlweCiphertextVector64 {
                version: GlweCiphertextVector64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableGlweCiphertextVector64 {
                version: GlweCiphertextVector64Version::V0,
                inner,
            } => Ok(GlweCiphertextVector64(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> GlweCiphertextVector64 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 32 bits integers. It deserializes a GLWE secret key entity.
impl EntityDeserializationEngine<&[u8], GlweSecretKey32> for DefaultSerializationEngine {
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
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<GlweSecretKey32, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableGlweSecretKey32 {
            version: GlweSecretKey32Version,
            inner: ImplGlweSecretKey<BinaryKeyKind, Vec<u32>>,
        }
        let deserialized: DeserializableGlweSecretKey32 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableGlweSecretKey32 {
                version: GlweSecretKey32Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableGlweSecretKey32 {
                version: GlweSecretKey32Version::V0,
                inner,
            } => Ok(GlweSecretKey32(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> GlweSecretKey32 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 64 bits integers. It deserializes a GLWE secret key entity.
impl EntityDeserializationEngine<&[u8], GlweSecretKey64> for DefaultSerializationEngine {
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
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<GlweSecretKey64, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableGlweSecretKey64 {
            version: GlweSecretKey64Version,
            inner: ImplGlweSecretKey<BinaryKeyKind, Vec<u64>>,
        }
        let deserialized: DeserializableGlweSecretKey64 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableGlweSecretKey64 {
                version: GlweSecretKey64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableGlweSecretKey64 {
                version: GlweSecretKey64Version::V0,
                inner,
            } => Ok(GlweSecretKey64(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> GlweSecretKey64 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 32 bits integers. It deserializes a LWE bootstrap key entity.
impl EntityDeserializationEngine<&[u8], LweBootstrapKey32> for DefaultSerializationEngine {
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
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<LweBootstrapKey32, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableLweBootstrapKey32 {
            version: LweBootstrapKey32Version,
            inner: ImplStandardBootstrapKey<Vec<u32>>,
        }
        let deserialized: DeserializableLweBootstrapKey32 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableLweBootstrapKey32 {
                version: LweBootstrapKey32Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableLweBootstrapKey32 {
                version: LweBootstrapKey32Version::V0,
                inner,
            } => Ok(LweBootstrapKey32(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> LweBootstrapKey32 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 64 bits integers. It deserializes a LWE bootstrap key entity.
impl EntityDeserializationEngine<&[u8], LweBootstrapKey64> for DefaultSerializationEngine {
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
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<LweBootstrapKey64, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableLweBootstrapKey64 {
            version: LweBootstrapKey64Version,
            inner: ImplStandardBootstrapKey<Vec<u64>>,
        }
        let deserialized: DeserializableLweBootstrapKey64 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableLweBootstrapKey64 {
                version: LweBootstrapKey64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableLweBootstrapKey64 {
                version: LweBootstrapKey64Version::V0,
                inner,
            } => Ok(LweBootstrapKey64(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> LweBootstrapKey64 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 32 bits integers. It deserializes a LWE ciphertext entity.
impl EntityDeserializationEngine<&[u8], LweCiphertext32> for DefaultSerializationEngine {
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
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<LweCiphertext32, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableLweCiphertext32 {
            version: LweCiphertext32Version,
            inner: ImplLweCiphertext<Vec<u32>>,
        }
        let deserialized: DeserializableLweCiphertext32 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableLweCiphertext32 {
                version: LweCiphertext32Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableLweCiphertext32 {
                version: LweCiphertext32Version::V0,
                inner,
            } => Ok(LweCiphertext32(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> LweCiphertext32 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 64 bits integers. It deserializes a LWE ciphertext entity.
impl EntityDeserializationEngine<&[u8], LweCiphertext64> for DefaultSerializationEngine {
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
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<LweCiphertext64, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableLweCiphertext64 {
            version: LweCiphertext64Version,
            inner: ImplLweCiphertext<Vec<u64>>,
        }
        let deserialized: DeserializableLweCiphertext64 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableLweCiphertext64 {
                version: LweCiphertext64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableLweCiphertext64 {
                version: LweCiphertext64Version::V0,
                inner,
            } => Ok(LweCiphertext64(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> LweCiphertext64 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 32 bits integers. It deserializes a LWE ciphertext vector entity.
impl EntityDeserializationEngine<&[u8], LweCiphertextVector32> for DefaultSerializationEngine {
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
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<LweCiphertextVector32, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableLweCiphertextVector32 {
            version: LweCiphertextVector32Version,
            inner: ImplLweList<Vec<u32>>,
        }
        let deserialized: DeserializableLweCiphertextVector32 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableLweCiphertextVector32 {
                version: LweCiphertextVector32Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableLweCiphertextVector32 {
                version: LweCiphertextVector32Version::V0,
                inner,
            } => Ok(LweCiphertextVector32(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> LweCiphertextVector32 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 64 bits integers. It deserializes a LWE ciphertext vector entity.
impl EntityDeserializationEngine<&[u8], LweCiphertextVector64> for DefaultSerializationEngine {
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
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<LweCiphertextVector64, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableLweCiphertextVector64 {
            version: LweCiphertextVector64Version,
            inner: ImplLweList<Vec<u64>>,
        }
        let deserialized: DeserializableLweCiphertextVector64 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableLweCiphertextVector64 {
                version: LweCiphertextVector64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableLweCiphertextVector64 {
                version: LweCiphertextVector64Version::V0,
                inner,
            } => Ok(LweCiphertextVector64(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> LweCiphertextVector64 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 32 bits integers. It deserializes a LWE keyswitch key entity.
impl EntityDeserializationEngine<&[u8], LweKeyswitchKey32> for DefaultSerializationEngine {
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
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<LweKeyswitchKey32, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableLweKeyswitchKey32 {
            version: LweKeyswitchKey32Version,
            inner: ImplLweKeyswitchKey<Vec<u32>>,
        }
        let deserialized: DeserializableLweKeyswitchKey32 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableLweKeyswitchKey32 {
                version: LweKeyswitchKey32Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableLweKeyswitchKey32 {
                version: LweKeyswitchKey32Version::V0,
                inner,
            } => Ok(LweKeyswitchKey32(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> LweKeyswitchKey32 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 64 bits integers. It deserializes a LWE keyswitch key entity.
impl EntityDeserializationEngine<&[u8], LweKeyswitchKey64> for DefaultSerializationEngine {
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
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<LweKeyswitchKey64, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableLweKeyswitchKey64 {
            version: LweKeyswitchKey64Version,
            inner: ImplLweKeyswitchKey<Vec<u64>>,
        }
        let deserialized: DeserializableLweKeyswitchKey64 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableLweKeyswitchKey64 {
                version: LweKeyswitchKey64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableLweKeyswitchKey64 {
                version: LweKeyswitchKey64Version::V0,
                inner,
            } => Ok(LweKeyswitchKey64(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> LweKeyswitchKey64 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 32 bits integers. It deserializes a LWE secret key entity.
impl EntityDeserializationEngine<&[u8], LweSecretKey32> for DefaultSerializationEngine {
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
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<LweSecretKey32, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableLweSecretKey32 {
            version: LweSecretKey32Version,
            inner: ImplLweSecretKey<BinaryKeyKind, Vec<u32>>,
        }
        let deserialized: DeserializableLweSecretKey32 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableLweSecretKey32 {
                version: LweSecretKey32Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableLweSecretKey32 {
                version: LweSecretKey32Version::V0,
                inner,
            } => Ok(LweSecretKey32(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> LweSecretKey32 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 64 bits integers. It deserializes a LWE secret key entity.
impl EntityDeserializationEngine<&[u8], LweSecretKey64> for DefaultSerializationEngine {
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
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<LweSecretKey64, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableLweSecretKey64 {
            version: LweSecretKey64Version,
            inner: ImplLweSecretKey<BinaryKeyKind, Vec<u64>>,
        }
        let deserialized: DeserializableLweSecretKey64 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableLweSecretKey64 {
                version: LweSecretKey64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableLweSecretKey64 {
                version: LweSecretKey64Version::V0,
                inner,
            } => Ok(LweSecretKey64(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> LweSecretKey64 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 32 bits integers. It deserializes a seeded LWE ciphertext entity.
impl EntityDeserializationEngine<&[u8], LweSeededCiphertext32> for DefaultSerializationEngine {
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
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<LweSeededCiphertext32, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableLweSeededCiphertext32 {
            version: LweSeededCiphertext32Version,
            inner: ImplLweSeededCiphertext<u32>,
        }
        let deserialized: DeserializableLweSeededCiphertext32 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableLweSeededCiphertext32 {
                version: LweSeededCiphertext32Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableLweSeededCiphertext32 {
                version: LweSeededCiphertext32Version::V0,
                inner,
            } => Ok(LweSeededCiphertext32(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> LweSeededCiphertext32 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 64 bits integers. It deserializes a seeded LWE ciphertext entity.
impl EntityDeserializationEngine<&[u8], LweSeededCiphertext64> for DefaultSerializationEngine {
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
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<LweSeededCiphertext64, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableLweSeededCiphertext64 {
            version: LweSeededCiphertext64Version,
            inner: ImplLweSeededCiphertext<u64>,
        }
        let deserialized: DeserializableLweSeededCiphertext64 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableLweSeededCiphertext64 {
                version: LweSeededCiphertext64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableLweSeededCiphertext64 {
                version: LweSeededCiphertext64Version::V0,
                inner,
            } => Ok(LweSeededCiphertext64(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> LweSeededCiphertext64 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 32 bits integers. It serializes a packing keyswitch key entity.
impl EntityDeserializationEngine<&[u8], PackingKeyswitchKey32> for DefaultSerializationEngine {
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
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<PackingKeyswitchKey32, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializablePackingKeyswitchKey32 {
            version: PackingKeyswitchKey32Version,
            inner: ImplPackingKeyswitchKey<Vec<u32>>,
        }
        let deserialized: DeserializablePackingKeyswitchKey32 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializablePackingKeyswitchKey32 {
                version: PackingKeyswitchKey32Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializablePackingKeyswitchKey32 {
                version: PackingKeyswitchKey32Version::V0,
                inner,
            } => Ok(PackingKeyswitchKey32(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> PackingKeyswitchKey32 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 64 bits integers. It deserializes a packing keyswitch key entity.
impl EntityDeserializationEngine<&[u8], PackingKeyswitchKey64> for DefaultSerializationEngine {
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
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<PackingKeyswitchKey64, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializablePackingKeyswitchKey64 {
            version: PackingKeyswitchKey64Version,
            inner: ImplPackingKeyswitchKey<Vec<u64>>,
        }
        let deserialized: DeserializablePackingKeyswitchKey64 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializablePackingKeyswitchKey64 {
                version: PackingKeyswitchKey64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializablePackingKeyswitchKey64 {
                version: PackingKeyswitchKey64Version::V0,
                inner,
            } => Ok(PackingKeyswitchKey64(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> PackingKeyswitchKey64 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 32 bits integers. It deserializes a plaintext entity.
impl EntityDeserializationEngine<&[u8], Plaintext32> for DefaultSerializationEngine {
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
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<Plaintext32, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializablePlaintext32 {
            version: Plaintext32Version,
            inner: ImplPlaintext<u32>,
        }
        let deserialized: DeserializablePlaintext32 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializablePlaintext32 {
                version: Plaintext32Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializablePlaintext32 {
                version: Plaintext32Version::V0,
                inner,
            } => Ok(Plaintext32(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> Plaintext32 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 64 bits integers. It deserializes a plaintext entity.
impl EntityDeserializationEngine<&[u8], Plaintext64> for DefaultSerializationEngine {
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
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<Plaintext64, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializablePlaintext64 {
            version: Plaintext64Version,
            inner: ImplPlaintext<u64>,
        }
        let deserialized: DeserializablePlaintext64 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializablePlaintext64 {
                version: Plaintext64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializablePlaintext64 {
                version: Plaintext64Version::V0,
                inner,
            } => Ok(Plaintext64(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> Plaintext64 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 32 bits integers. It deserializes a plaintext vector entity.
impl EntityDeserializationEngine<&[u8], PlaintextVector32> for DefaultSerializationEngine {
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
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<PlaintextVector32, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializablePlaintextVector32 {
            version: PlaintextVector32Version,
            inner: ImplPlaintextList<Vec<u32>>,
        }
        let deserialized: DeserializablePlaintextVector32 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializablePlaintextVector32 {
                version: PlaintextVector32Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializablePlaintextVector32 {
                version: PlaintextVector32Version::V0,
                inner,
            } => Ok(PlaintextVector32(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> PlaintextVector32 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 64 bits integers. It deserializes a plaintext vector entity.
impl EntityDeserializationEngine<&[u8], PlaintextVector64> for DefaultSerializationEngine {
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
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<PlaintextVector64, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializablePlaintextVector64 {
            version: PlaintextVector64Version,
            inner: ImplPlaintextList<Vec<u64>>,
        }
        let deserialized: DeserializablePlaintextVector64 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializablePlaintextVector64 {
                version: PlaintextVector64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializablePlaintextVector64 {
                version: PlaintextVector64Version::V0,
                inner,
            } => Ok(PlaintextVector64(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> PlaintextVector64 {
        self.deserialize(serialized).unwrap()
    }
}
