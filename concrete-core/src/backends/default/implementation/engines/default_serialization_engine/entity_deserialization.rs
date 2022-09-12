#![allow(clippy::missing_safety_doc)]
use crate::commons::crypto::bootstrap::{
    StandardBootstrapKey as ImplStandardBootstrapKey,
    StandardSeededBootstrapKey as ImplStandardSeededBootstrapKey,
};
use crate::commons::crypto::encoding::{
    Cleartext as ImplCleartext, CleartextList as ImplCleartextList,
    FloatEncoder as ImplFloatEncoder, Plaintext as ImplPlaintext,
    PlaintextList as ImplPlaintextList,
};
use crate::commons::crypto::ggsw::{
    StandardGgswCiphertext as ImplStandardGgswCiphertext,
    StandardGgswSeededCiphertext as ImplStandardGgswSeededCiphertext,
};
use crate::commons::crypto::glwe::{
    GlweCiphertext as ImplGlweCiphertext, GlweList as ImplGlweList,
    GlweSeededCiphertext as ImplGlweSeededCiphertext, GlweSeededList as ImplGlweSeededList,
    LwePackingKeyswitchKey as ImplLwePackingKeyswitchKey,
};
use crate::commons::crypto::lwe::{
    LweCiphertext as ImplLweCiphertext, LweKeyswitchKey as ImplLweKeyswitchKey,
    LweList as ImplLweList, LweSeededCiphertext as ImplLweSeededCiphertext,
    LweSeededKeyswitchKey as ImplLweSeededKeyswitchKey, LweSeededList as ImplLweSeededList,
};
use crate::commons::crypto::secret::{
    GlweSecretKey as ImplGlweSecretKey, LweSecretKey as ImplLweSecretKey,
};
use crate::prelude::{
    BinaryKeyKind, Cleartext32, Cleartext32Version, Cleartext64, Cleartext64Version,
    CleartextArray32, CleartextArray32Version, CleartextArray64, CleartextArray64Version,
    CleartextArrayF64, CleartextArrayF64Version, CleartextF64, CleartextF64Version,
    DefaultSerializationEngine, DefaultSerializationError, EntityDeserializationEngine,
    EntityDeserializationError, FloatEncoder, FloatEncoderArray, FloatEncoderArrayVersion,
    FloatEncoderVersion, GgswCiphertext32, GgswCiphertext32Version, GgswCiphertext64,
    GgswCiphertext64Version, GgswSeededCiphertext32, GgswSeededCiphertext32Version,
    GgswSeededCiphertext64, GgswSeededCiphertext64Version, GlweCiphertext32,
    GlweCiphertext32Version, GlweCiphertext64, GlweCiphertext64Version, GlweCiphertextArray32,
    GlweCiphertextArray32Version, GlweCiphertextArray64, GlweCiphertextArray64Version,
    GlweSecretKey32, GlweSecretKey32Version, GlweSecretKey64, GlweSecretKey64Version,
    GlweSeededCiphertext32, GlweSeededCiphertext32Version, GlweSeededCiphertext64,
    GlweSeededCiphertext64Version, GlweSeededCiphertextArray32, GlweSeededCiphertextArray32Version,
    GlweSeededCiphertextArray64, GlweSeededCiphertextArray64Version, LweBootstrapKey32,
    LweBootstrapKey32Version, LweBootstrapKey64, LweBootstrapKey64Version, LweCiphertext32,
    LweCiphertext32Version, LweCiphertext64, LweCiphertext64Version, LweCiphertextArray32,
    LweCiphertextArray32Version, LweCiphertextArray64, LweCiphertextArray64Version,
    LweKeyswitchKey32, LweKeyswitchKey32Version, LweKeyswitchKey64, LweKeyswitchKey64Version,
    LwePackingKeyswitchKey32, LwePackingKeyswitchKey32Version, LwePackingKeyswitchKey64,
    LwePackingKeyswitchKey64Version, LweSecretKey32, LweSecretKey32Version, LweSecretKey64,
    LweSecretKey64Version, LweSeededBootstrapKey32, LweSeededBootstrapKey32Version,
    LweSeededBootstrapKey64, LweSeededBootstrapKey64Version, LweSeededCiphertext32,
    LweSeededCiphertext32Version, LweSeededCiphertext64, LweSeededCiphertext64Version,
    LweSeededCiphertextArray32, LweSeededCiphertextArray32Version, LweSeededCiphertextArray64,
    LweSeededCiphertextArray64Version, LweSeededKeyswitchKey32, LweSeededKeyswitchKey32Version,
    LweSeededKeyswitchKey64, LweSeededKeyswitchKey64Version, Plaintext32, Plaintext32Version,
    Plaintext64, Plaintext64Version, PlaintextArray32, PlaintextArray32Version, PlaintextArray64,
    PlaintextArray64Version,
};
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
    /// let cleartext: Cleartext32 = engine.create_cleartext_from(&input)?;
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&cleartext)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(cleartext, recovered);
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
    /// let cleartext: Cleartext64 = engine.create_cleartext_from(&input)?;
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&cleartext)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(cleartext, recovered);
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
/// operates on 64 bits integers. It deserializes a floating point cleartext entity.
impl EntityDeserializationEngine<&[u8], CleartextF64> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let input: f64 = 3.;
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let cleartext: CleartextF64 = engine.create_cleartext_from(&input)?;
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&cleartext)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(cleartext, recovered);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<CleartextF64, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableCleartextF64 {
            version: CleartextF64Version,
            inner: ImplCleartext<f64>,
        }
        let deserialized: DeserializableCleartextF64 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableCleartextF64 {
                version: CleartextF64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableCleartextF64 {
                version: CleartextF64Version::V0,
                inner,
            } => Ok(CleartextF64(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> CleartextF64 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 32 bits integers. It deserializes a cleartext array entity.
impl EntityDeserializationEngine<&[u8], CleartextArray32> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{CleartextCount, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let input = vec![3_u32; 100];
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let cleartext_array: CleartextArray32 = engine.create_cleartext_array_from(&input)?;
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&cleartext_array)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(cleartext_array, recovered);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<CleartextArray32, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableCleartextArray32 {
            version: CleartextArray32Version,
            inner: ImplCleartextList<Vec<u32>>,
        }
        let deserialized: DeserializableCleartextArray32 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableCleartextArray32 {
                version: CleartextArray32Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableCleartextArray32 {
                version: CleartextArray32Version::V0,
                inner,
            } => Ok(CleartextArray32(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> CleartextArray32 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 64 bits integers. It deserializes a cleartext array entity.
impl EntityDeserializationEngine<&[u8], CleartextArray64> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{CleartextCount, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let input = vec![3_u64; 100];
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let cleartext_array: CleartextArray64 = engine.create_cleartext_array_from(&input)?;
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&cleartext_array)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(cleartext_array, recovered);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<CleartextArray64, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableCleartextArray64 {
            version: CleartextArray64Version,
            inner: ImplCleartextList<Vec<u64>>,
        }
        let deserialized: DeserializableCleartextArray64 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableCleartextArray64 {
                version: CleartextArray64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableCleartextArray64 {
                version: CleartextArray64Version::V0,
                inner,
            } => Ok(CleartextArray64(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> CleartextArray64 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 64 bits integers. It deserializes a floating point cleartext array entity.
impl EntityDeserializationEngine<&[u8], CleartextArrayF64> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{CleartextCount, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let input = vec![3.0_f64; 100];
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let cleartext_array: CleartextArrayF64 = engine.create_cleartext_array_from(&input)?;
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&cleartext_array)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(cleartext_array, recovered);
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<CleartextArrayF64, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableCleartextArrayF64 {
            version: CleartextArrayF64Version,
            inner: ImplCleartextList<Vec<f64>>,
        }
        let deserialized: DeserializableCleartextArrayF64 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableCleartextArrayF64 {
                version: CleartextArrayF64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableCleartextArrayF64 {
                version: CleartextArrayF64Version::V0,
                inner,
            } => Ok(CleartextArrayF64(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> CleartextArrayF64 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 32 bits integers. It deserializes a GGSW ciphertext entity.
impl EntityDeserializationEngine<&[u8], GgswCiphertext32> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize, Variance, *,
    /// };
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
    /// let key: GlweSecretKey32 =
    ///     engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext = engine.create_plaintext_from(&input)?;
    ///
    /// let ciphertext =
    ///     engine.encrypt_scalar_ggsw_ciphertext(&key, &plaintext, noise, level, base_log)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&ciphertext)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(ciphertext, recovered);
    ///
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
    /// use concrete_core::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize, Variance, *,
    /// };
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
    /// let key: GlweSecretKey64 =
    ///     engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext = engine.create_plaintext_from(&input)?;
    ///
    /// let ciphertext =
    ///     engine.encrypt_scalar_ggsw_ciphertext(&key, &plaintext, noise, level, base_log)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&ciphertext)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(ciphertext, recovered);
    ///
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
/// operates on 32 bits integers. It deserializes a seeded GGSW ciphertext entity.
impl EntityDeserializationEngine<&[u8], GgswSeededCiphertext32> for DefaultSerializationEngine {
    /// TODO
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<GgswSeededCiphertext32, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableGgswSeededCiphertext32 {
            version: GgswSeededCiphertext32Version,
            inner: ImplStandardGgswSeededCiphertext<Vec<u32>>,
        }
        let deserialized: DeserializableGgswSeededCiphertext32 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableGgswSeededCiphertext32 {
                version: GgswSeededCiphertext32Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableGgswSeededCiphertext32 {
                version: GgswSeededCiphertext32Version::V0,
                inner,
            } => Ok(GgswSeededCiphertext32(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> GgswSeededCiphertext32 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 64 bits integers. It deserializes a seeded GGSW ciphertext entity.
impl EntityDeserializationEngine<&[u8], GgswSeededCiphertext64> for DefaultSerializationEngine {
    /// TODO
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<GgswSeededCiphertext64, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableGgswSeededCiphertext64 {
            version: GgswSeededCiphertext64Version,
            inner: ImplStandardGgswSeededCiphertext<Vec<u64>>,
        }
        let deserialized: DeserializableGgswSeededCiphertext64 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableGgswSeededCiphertext64 {
                version: GgswSeededCiphertext64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableGgswSeededCiphertext64 {
                version: GgswSeededCiphertext64Version::V0,
                inner,
            } => Ok(GgswSeededCiphertext64(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> GgswSeededCiphertext64 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 32 bits integers. It deserializes a GLWE ciphertext entity.
impl EntityDeserializationEngine<&[u8], GlweCiphertext32> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{GlweDimension, PolynomialSize, Variance, *};
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
    /// let key: GlweSecretKey32 =
    ///     engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_array = engine.create_plaintext_array_from(&input)?;
    ///
    /// let ciphertext = engine.encrypt_glwe_ciphertext(&key, &plaintext_array, noise)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&ciphertext)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(ciphertext, recovered);
    ///
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
    /// use concrete_core::prelude::{GlweDimension, PolynomialSize, Variance, *};
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
    /// let key: GlweSecretKey64 =
    ///     engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_array = engine.create_plaintext_array_from(&input)?;
    ///
    /// let ciphertext = engine.encrypt_glwe_ciphertext(&key, &plaintext_array, noise)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&ciphertext)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(ciphertext, recovered);
    ///
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
/// operates on 32 bits integers. It deserializes a GLWE ciphertext array entity.
impl EntityDeserializationEngine<&[u8], GlweCiphertextArray32> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{GlweCiphertextCount, GlweDimension, PolynomialSize, Variance, *};
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
    /// let key: GlweSecretKey32 =
    ///     engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_array = engine.create_plaintext_array_from(&input)?;
    ///
    /// let ciphertext_array = engine.encrypt_glwe_ciphertext_array(&key, &plaintext_array, noise)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&ciphertext_array)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(ciphertext_array, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<GlweCiphertextArray32, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableGlweCiphertextArray32 {
            version: GlweCiphertextArray32Version,
            inner: ImplGlweList<Vec<u32>>,
        }
        let deserialized: DeserializableGlweCiphertextArray32 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableGlweCiphertextArray32 {
                version: GlweCiphertextArray32Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableGlweCiphertextArray32 {
                version: GlweCiphertextArray32Version::V0,
                inner,
            } => Ok(GlweCiphertextArray32(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> GlweCiphertextArray32 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 64 bits integers. It deserializes a GLWE ciphertext array entity.
impl EntityDeserializationEngine<&[u8], GlweCiphertextArray64> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{GlweCiphertextCount, GlweDimension, PolynomialSize, Variance, *};
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
    /// let key: GlweSecretKey64 =
    ///     engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_array = engine.create_plaintext_array_from(&input)?;
    ///
    /// let ciphertext_array = engine.encrypt_glwe_ciphertext_array(&key, &plaintext_array, noise)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&ciphertext_array)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(ciphertext_array, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<GlweCiphertextArray64, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableGlweCiphertextArray64 {
            version: GlweCiphertextArray64Version,
            inner: ImplGlweList<Vec<u64>>,
        }
        let deserialized: DeserializableGlweCiphertextArray64 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableGlweCiphertextArray64 {
                version: GlweCiphertextArray64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableGlweCiphertextArray64 {
                version: GlweCiphertextArray64Version::V0,
                inner,
            } => Ok(GlweCiphertextArray64(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> GlweCiphertextArray64 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 32 bits integers. It deserializes a GLWE secret key entity.
impl EntityDeserializationEngine<&[u8], GlweSecretKey32> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{GlweDimension, PolynomialSize, *};
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
    ///     engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&glwe_secret_key)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(glwe_secret_key, recovered);
    ///
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
    /// use concrete_core::prelude::{GlweDimension, PolynomialSize, *};
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
    ///     engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&glwe_secret_key)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(glwe_secret_key, recovered);
    ///
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
/// operates on 32 bits integers. It deserializes a GLWE seeded ciphertext entity.
impl EntityDeserializationEngine<&[u8], GlweSeededCiphertext32> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{GlweDimension, PolynomialSize, Variance, *};
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
    /// let key: GlweSecretKey32 =
    ///     engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_array = engine.create_plaintext_array_from(&input)?;
    ///
    /// let seeded_ciphertext = engine.encrypt_glwe_seeded_ciphertext(&key, &plaintext_array, noise)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&seeded_ciphertext)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(seeded_ciphertext, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<GlweSeededCiphertext32, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableGlweSeededCiphertext32 {
            version: GlweSeededCiphertext32Version,
            inner: ImplGlweSeededCiphertext<Vec<u32>>,
        }
        let deserialized: DeserializableGlweSeededCiphertext32 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableGlweSeededCiphertext32 {
                version: GlweSeededCiphertext32Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableGlweSeededCiphertext32 {
                version: GlweSeededCiphertext32Version::V0,
                inner,
            } => Ok(GlweSeededCiphertext32(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> GlweSeededCiphertext32 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 64 bits integers. It deserializes a GLWE seeded ciphertext entity.
impl EntityDeserializationEngine<&[u8], GlweSeededCiphertext64> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{GlweDimension, PolynomialSize, Variance, *};
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
    /// let key: GlweSecretKey64 =
    ///     engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_array = engine.create_plaintext_array_from(&input)?;
    ///
    /// let seeded_ciphertext = engine.encrypt_glwe_seeded_ciphertext(&key, &plaintext_array, noise)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&seeded_ciphertext)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(seeded_ciphertext, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<GlweSeededCiphertext64, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableGlweSeededCiphertext64 {
            version: GlweSeededCiphertext64Version,
            inner: ImplGlweSeededCiphertext<Vec<u64>>,
        }
        let deserialized: DeserializableGlweSeededCiphertext64 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableGlweSeededCiphertext64 {
                version: GlweSeededCiphertext64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableGlweSeededCiphertext64 {
                version: GlweSeededCiphertext64Version::V0,
                inner,
            } => Ok(GlweSeededCiphertext64(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> GlweSeededCiphertext64 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 32 bits integers. It deserializes a GLWE seeded ciphertext array entity.
impl EntityDeserializationEngine<&[u8], GlweSeededCiphertextArray32>
    for DefaultSerializationEngine
{
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{GlweCiphertextCount, GlweDimension, PolynomialSize, Variance, *};
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
    /// let key: GlweSecretKey32 =
    ///     engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_array = engine.create_plaintext_array_from(&input)?;
    ///
    /// let seeded_ciphertext_array =
    ///     engine.encrypt_glwe_seeded_ciphertext_array(&key, &plaintext_array, noise)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&seeded_ciphertext_array)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(seeded_ciphertext_array, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<GlweSeededCiphertextArray32, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableGlweSeededCiphertextArray32 {
            version: GlweSeededCiphertextArray32Version,
            inner: ImplGlweSeededList<Vec<u32>>,
        }
        let deserialized: DeserializableGlweSeededCiphertextArray32 =
            bincode::deserialize(serialized)
                .map_err(DefaultSerializationError::Deserialization)
                .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableGlweSeededCiphertextArray32 {
                version: GlweSeededCiphertextArray32Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableGlweSeededCiphertextArray32 {
                version: GlweSeededCiphertextArray32Version::V0,
                inner,
            } => Ok(GlweSeededCiphertextArray32(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> GlweSeededCiphertextArray32 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 64 bits integers. It deserializes a GLWE seeded ciphertext array entity.
impl EntityDeserializationEngine<&[u8], GlweSeededCiphertextArray64>
    for DefaultSerializationEngine
{
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{GlweCiphertextCount, GlweDimension, PolynomialSize, Variance, *};
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
    /// let key: GlweSecretKey64 =
    ///     engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_array = engine.create_plaintext_array_from(&input)?;
    ///
    /// let seeded_ciphertext_array =
    ///     engine.encrypt_glwe_seeded_ciphertext_array(&key, &plaintext_array, noise)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&seeded_ciphertext_array)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(seeded_ciphertext_array, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<GlweSeededCiphertextArray64, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableGlweSeededCiphertextArray64 {
            version: GlweSeededCiphertextArray64Version,
            inner: ImplGlweSeededList<Vec<u64>>,
        }
        let deserialized: DeserializableGlweSeededCiphertextArray64 =
            bincode::deserialize(serialized)
                .map_err(DefaultSerializationError::Deserialization)
                .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableGlweSeededCiphertextArray64 {
                version: GlweSeededCiphertextArray64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableGlweSeededCiphertextArray64 {
                version: GlweSeededCiphertextArray64Version::V0,
                inner,
            } => Ok(GlweSeededCiphertextArray64(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> GlweSeededCiphertextArray64 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 32 bits integers. It deserializes a LWE bootstrap key entity.
impl EntityDeserializationEngine<&[u8], LweBootstrapKey32> for DefaultSerializationEngine {
    /// # Example
    /// ```
    /// use concrete_core::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    ///     Variance, *,
    /// };
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
    /// let lwe_sk: LweSecretKey32 = engine.generate_new_lwe_secret_key(lwe_dim)?;
    /// let glwe_sk: GlweSecretKey32 = engine.generate_new_glwe_secret_key(glwe_dim, poly_size)?;
    ///
    /// let bsk: LweBootstrapKey32 =
    ///     engine.generate_new_lwe_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&bsk)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(bsk, recovered);
    ///
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
    /// use concrete_core::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    ///     Variance, *,
    /// };
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
    /// let lwe_sk: LweSecretKey64 = engine.generate_new_lwe_secret_key(lwe_dim)?;
    /// let glwe_sk: GlweSecretKey64 = engine.generate_new_glwe_secret_key(glwe_dim, poly_size)?;
    ///
    /// let bsk: LweBootstrapKey64 =
    ///     engine.generate_new_lwe_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&bsk)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(bsk, recovered);
    ///
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
    /// use concrete_core::prelude::{LweDimension, Variance, *};
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
    /// let key: LweSecretKey32 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext = engine.create_plaintext_from(&input)?;
    ///
    /// let ciphertext = engine.encrypt_lwe_ciphertext(&key, &plaintext, noise)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&ciphertext)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(ciphertext, recovered);
    ///
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
    /// use concrete_core::prelude::Variance;
    /// use concrete_core::prelude::LweDimension;
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
    /// let key: LweSecretKey64 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext = engine.create_plaintext_from(&input)?;
    ///
    /// let ciphertext = engine.encrypt_lwe_ciphertext(&key, &plaintext, noise)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&ciphertext)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(ciphertext, recovered);
    ///
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
/// operates on 32 bits integers. It deserializes a LWE ciphertext array entity.
impl EntityDeserializationEngine<&[u8], LweCiphertextArray32> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{LweCiphertextCount, LweDimension, Variance, *};
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
    /// let key: LweSecretKey32 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext_array: PlaintextArray32 = engine.create_plaintext_array_from(&input)?;
    ///
    /// let mut ciphertext_array: LweCiphertextArray32 =
    ///     engine.encrypt_lwe_ciphertext_array(&key, &plaintext_array, noise)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&ciphertext_array)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(ciphertext_array, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<LweCiphertextArray32, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableLweCiphertextArray32 {
            version: LweCiphertextArray32Version,
            inner: ImplLweList<Vec<u32>>,
        }
        let deserialized: DeserializableLweCiphertextArray32 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableLweCiphertextArray32 {
                version: LweCiphertextArray32Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableLweCiphertextArray32 {
                version: LweCiphertextArray32Version::V0,
                inner,
            } => Ok(LweCiphertextArray32(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> LweCiphertextArray32 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 64 bits integers. It deserializes a LWE ciphertext array entity.
impl EntityDeserializationEngine<&[u8], LweCiphertextArray64> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{LweCiphertextCount, LweDimension, Variance, *};
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
    /// let key: LweSecretKey64 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext_array: PlaintextArray64 = engine.create_plaintext_array_from(&input)?;
    ///
    /// let mut ciphertext_array: LweCiphertextArray64 =
    ///     engine.encrypt_lwe_ciphertext_array(&key, &plaintext_array, noise)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&ciphertext_array)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(ciphertext_array, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<LweCiphertextArray64, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableLweCiphertextArray64 {
            version: LweCiphertextArray64Version,
            inner: ImplLweList<Vec<u64>>,
        }
        let deserialized: DeserializableLweCiphertextArray64 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableLweCiphertextArray64 {
                version: LweCiphertextArray64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableLweCiphertextArray64 {
                version: LweCiphertextArray64Version::V0,
                inner,
            } => Ok(LweCiphertextArray64(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> LweCiphertextArray64 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 32 bits integers. It deserializes a LWE keyswitch key entity.
impl EntityDeserializationEngine<&[u8], LweKeyswitchKey32> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, LweDimension, Variance, *,
    /// };
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
    /// let input_key: LweSecretKey32 = engine.generate_new_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: LweSecretKey32 = engine.generate_new_lwe_secret_key(output_lwe_dimension)?;
    ///
    /// let keyswitch_key = engine.generate_new_lwe_keyswitch_key(
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
    /// use concrete_core::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, LweDimension, Variance, *,
    /// };
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
    /// let input_key: LweSecretKey64 = engine.generate_new_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: LweSecretKey64 = engine.generate_new_lwe_secret_key(output_lwe_dimension)?;
    ///
    /// let keyswitch_key = engine.generate_new_lwe_keyswitch_key(
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
    /// use concrete_core::prelude::{LweDimension, *};
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
    /// let lwe_secret_key: LweSecretKey32 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&lwe_secret_key)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(lwe_secret_key, recovered);
    ///
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
    /// use concrete_core::prelude::{LweDimension, *};
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
    /// let lwe_secret_key: LweSecretKey64 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&lwe_secret_key)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(lwe_secret_key, recovered);
    ///
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
/// operates on 32 bits integers. It deserializes a seeded LWE bootstrap key entity.
impl EntityDeserializationEngine<&[u8], LweSeededBootstrapKey32> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    ///     Variance, *,
    /// };
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
    /// let lwe_sk: LweSecretKey32 = engine.generate_new_lwe_secret_key(lwe_dim)?;
    /// let glwe_sk: GlweSecretKey32 = engine.generate_new_glwe_secret_key(glwe_dim, poly_size)?;
    ///
    /// let bsk: LweSeededBootstrapKey32 =
    ///     engine.generate_new_lwe_seeded_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&bsk)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    ///
    /// assert_eq!(bsk, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<LweSeededBootstrapKey32, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableLweSeededBootstrapKey32 {
            version: LweSeededBootstrapKey32Version,
            inner: ImplStandardSeededBootstrapKey<Vec<u32>>,
        }
        let deserialized: DeserializableLweSeededBootstrapKey32 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableLweSeededBootstrapKey32 {
                version: LweSeededBootstrapKey32Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableLweSeededBootstrapKey32 {
                version: LweSeededBootstrapKey32Version::V0,
                inner,
            } => Ok(LweSeededBootstrapKey32(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> LweSeededBootstrapKey32 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 64 bits integers. It deserializes a seeded LWE bootstrap key entity.
impl EntityDeserializationEngine<&[u8], LweSeededBootstrapKey64> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    ///     Variance, *,
    /// };
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
    /// let lwe_sk: LweSecretKey64 = engine.generate_new_lwe_secret_key(lwe_dim)?;
    /// let glwe_sk: GlweSecretKey64 = engine.generate_new_glwe_secret_key(glwe_dim, poly_size)?;
    ///
    /// let bsk: LweSeededBootstrapKey64 =
    ///     engine.generate_new_lwe_seeded_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&bsk)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    ///
    /// assert_eq!(bsk, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<LweSeededBootstrapKey64, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableLweSeededBootstrapKey64 {
            version: LweSeededBootstrapKey64Version,
            inner: ImplStandardSeededBootstrapKey<Vec<u64>>,
        }
        let deserialized: DeserializableLweSeededBootstrapKey64 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableLweSeededBootstrapKey64 {
                version: LweSeededBootstrapKey64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableLweSeededBootstrapKey64 {
                version: LweSeededBootstrapKey64Version::V0,
                inner,
            } => Ok(LweSeededBootstrapKey64(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> LweSeededBootstrapKey64 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 32 bits integers. It deserializes a seeded LWE ciphertext entity.
impl EntityDeserializationEngine<&[u8], LweSeededCiphertext32> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{LweDimension, Variance, *};
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
    /// let key: LweSecretKey32 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext = engine.create_plaintext_from(&input)?;
    ///
    /// let ciphertext: LweSeededCiphertext32 =
    ///     engine.encrypt_lwe_seeded_ciphertext(&key, &plaintext, noise)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&ciphertext)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(ciphertext, recovered);
    ///
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
    /// use concrete_core::prelude::{LweDimension, Variance, *};
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
    /// let key: LweSecretKey64 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext = engine.create_plaintext_from(&input)?;
    ///
    /// let ciphertext: LweSeededCiphertext64 =
    ///     engine.encrypt_lwe_seeded_ciphertext(&key, &plaintext, noise)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&ciphertext)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(ciphertext, recovered);
    ///
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
/// operates on 32 bits integers. It deserializes a seeded LWE ciphertext array entity.
impl EntityDeserializationEngine<&[u8], LweSeededCiphertextArray32> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{LweCiphertextCount, LweDimension, Variance, *};
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
    /// let key: LweSecretKey32 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext_array: PlaintextArray32 = engine.create_plaintext_array_from(&input)?;
    ///
    /// let mut ciphertext_array: LweSeededCiphertextArray32 =
    ///     engine.encrypt_lwe_seeded_ciphertext_array(&key, &plaintext_array, noise)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&ciphertext_array)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(ciphertext_array, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<LweSeededCiphertextArray32, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableLweSeededCiphertextArray32 {
            version: LweSeededCiphertextArray32Version,
            inner: ImplLweSeededList<Vec<u32>>,
        }
        let deserialized: DeserializableLweSeededCiphertextArray32 =
            bincode::deserialize(serialized)
                .map_err(DefaultSerializationError::Deserialization)
                .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableLweSeededCiphertextArray32 {
                version: LweSeededCiphertextArray32Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableLweSeededCiphertextArray32 {
                version: LweSeededCiphertextArray32Version::V0,
                inner,
            } => Ok(LweSeededCiphertextArray32(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> LweSeededCiphertextArray32 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 64 bits integers. It deserializes a seeded LWE ciphertext array entity.
impl EntityDeserializationEngine<&[u8], LweSeededCiphertextArray64> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{LweCiphertextCount, LweDimension, Variance, *};
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
    /// let key: LweSecretKey64 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let plaintext_array: PlaintextArray64 = engine.create_plaintext_array_from(&input)?;
    ///
    /// let mut ciphertext_array: LweSeededCiphertextArray64 =
    ///     engine.encrypt_lwe_seeded_ciphertext_array(&key, &plaintext_array, noise)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&ciphertext_array)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(ciphertext_array, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<LweSeededCiphertextArray64, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableLweSeededCiphertextArray64 {
            version: LweSeededCiphertextArray64Version,
            inner: ImplLweSeededList<Vec<u64>>,
        }
        let deserialized: DeserializableLweSeededCiphertextArray64 =
            bincode::deserialize(serialized)
                .map_err(DefaultSerializationError::Deserialization)
                .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableLweSeededCiphertextArray64 {
                version: LweSeededCiphertextArray64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableLweSeededCiphertextArray64 {
                version: LweSeededCiphertextArray64Version::V0,
                inner,
            } => Ok(LweSeededCiphertextArray64(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> LweSeededCiphertextArray64 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 32 bits integers. It deserializes a seeded LWE ciphertext keyswitch key entity.
impl EntityDeserializationEngine<&[u8], LweSeededKeyswitchKey32> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, LweDimension, Variance, *,
    /// };
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
    /// let input_key: LweSecretKey32 = engine.generate_new_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: LweSecretKey32 = engine.generate_new_lwe_secret_key(output_lwe_dimension)?;
    ///
    /// let seeded_keyswitch_key = engine.generate_new_lwe_seeded_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     decomposition_level_count,
    ///     decomposition_base_log,
    ///     noise,
    /// )?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&seeded_keyswitch_key)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(seeded_keyswitch_key, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<LweSeededKeyswitchKey32, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableLweSeededKeyswitchKey32 {
            version: LweSeededKeyswitchKey32Version,
            inner: ImplLweSeededKeyswitchKey<Vec<u32>>,
        }
        let deserialized: DeserializableLweSeededKeyswitchKey32 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableLweSeededKeyswitchKey32 {
                version: LweSeededKeyswitchKey32Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableLweSeededKeyswitchKey32 {
                version: LweSeededKeyswitchKey32Version::V0,
                inner,
            } => Ok(LweSeededKeyswitchKey32(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> LweSeededKeyswitchKey32 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 64 bits integers. It deserializes a seeded LWE ciphertext keyswitch key entity.
impl EntityDeserializationEngine<&[u8], LweSeededKeyswitchKey64> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, LweDimension, Variance, *,
    /// };
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
    /// let input_key: LweSecretKey64 = engine.generate_new_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: LweSecretKey64 = engine.generate_new_lwe_secret_key(output_lwe_dimension)?;
    ///
    /// let seeded_keyswitch_key = engine.generate_new_lwe_seeded_keyswitch_key(
    ///     &input_key,
    ///     &output_key,
    ///     decomposition_level_count,
    ///     decomposition_base_log,
    ///     noise,
    /// )?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&seeded_keyswitch_key)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(seeded_keyswitch_key, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<LweSeededKeyswitchKey64, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableLweSeededKeyswitchKey64 {
            version: LweSeededKeyswitchKey64Version,
            inner: ImplLweSeededKeyswitchKey<Vec<u64>>,
        }
        let deserialized: DeserializableLweSeededKeyswitchKey64 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableLweSeededKeyswitchKey64 {
                version: LweSeededKeyswitchKey64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableLweSeededKeyswitchKey64 {
                version: LweSeededKeyswitchKey64Version::V0,
                inner,
            } => Ok(LweSeededKeyswitchKey64(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> LweSeededKeyswitchKey64 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 32 bits integers. It serializes a packing keyswitch key entity.
impl EntityDeserializationEngine<&[u8], LwePackingKeyswitchKey32> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, LweDimension, Variance, *,
    /// };
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
    /// let input_key: LweSecretKey32 = engine.generate_new_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: LweSecretKey32 = engine.generate_new_lwe_secret_key(output_lwe_dimension)?;
    ///
    /// let packing_keyswitch_key = engine.generate_new_lwe_keyswitch_key(
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
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<LwePackingKeyswitchKey32, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializablePackingKeyswitchKey32 {
            version: LwePackingKeyswitchKey32Version,
            inner: ImplLwePackingKeyswitchKey<Vec<u32>>,
        }
        let deserialized: DeserializablePackingKeyswitchKey32 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializablePackingKeyswitchKey32 {
                version: LwePackingKeyswitchKey32Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializablePackingKeyswitchKey32 {
                version: LwePackingKeyswitchKey32Version::V0,
                inner,
            } => Ok(LwePackingKeyswitchKey32(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> LwePackingKeyswitchKey32 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 64 bits integers. It deserializes a packing keyswitch key entity.
impl EntityDeserializationEngine<&[u8], LwePackingKeyswitchKey64> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, LweDimension, Variance, *,
    /// };
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
    /// let input_key: LweSecretKey64 = engine.generate_new_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: LweSecretKey64 = engine.generate_new_lwe_secret_key(output_lwe_dimension)?;
    ///
    /// let packing_keyswitch_key = engine.generate_new_lwe_keyswitch_key(
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
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<LwePackingKeyswitchKey64, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializablePackingKeyswitchKey64 {
            version: LwePackingKeyswitchKey64Version,
            inner: ImplLwePackingKeyswitchKey<Vec<u64>>,
        }
        let deserialized: DeserializablePackingKeyswitchKey64 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializablePackingKeyswitchKey64 {
                version: LwePackingKeyswitchKey64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializablePackingKeyswitchKey64 {
                version: LwePackingKeyswitchKey64Version::V0,
                inner,
            } => Ok(LwePackingKeyswitchKey64(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> LwePackingKeyswitchKey64 {
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
    /// let plaintext: Plaintext32 = engine.create_plaintext_from(&input)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&plaintext)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(plaintext, recovered);
    ///
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
    /// let plaintext: Plaintext64 = engine.create_plaintext_from(&input)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&plaintext)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(plaintext, recovered);
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
/// operates on 32 bits integers. It deserializes a plaintext array entity.
impl EntityDeserializationEngine<&[u8], PlaintextArray32> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{PlaintextCount, *};
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
    /// let plaintext_array: PlaintextArray32 = engine.create_plaintext_array_from(&input)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&plaintext_array)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(plaintext_array, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<PlaintextArray32, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializablePlaintextArray32 {
            version: PlaintextArray32Version,
            inner: ImplPlaintextList<Vec<u32>>,
        }
        let deserialized: DeserializablePlaintextArray32 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializablePlaintextArray32 {
                version: PlaintextArray32Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializablePlaintextArray32 {
                version: PlaintextArray32Version::V0,
                inner,
            } => Ok(PlaintextArray32(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> PlaintextArray32 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 64 bits integers. It deserializes a plaintext array entity.
impl EntityDeserializationEngine<&[u8], PlaintextArray64> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{PlaintextCount, *};
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
    /// let plaintext_array: PlaintextArray64 = engine.create_plaintext_array_from(&input)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&plaintext_array)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(plaintext_array, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<PlaintextArray64, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializablePlaintextArray64 {
            version: PlaintextArray64Version,
            inner: ImplPlaintextList<Vec<u64>>,
        }
        let deserialized: DeserializablePlaintextArray64 = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializablePlaintextArray64 {
                version: PlaintextArray64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializablePlaintextArray64 {
                version: PlaintextArray64Version::V0,
                inner,
            } => Ok(PlaintextArray64(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> PlaintextArray64 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 64 bits integers. It deserializes a float encoder entity.
impl EntityDeserializationEngine<&[u8], FloatEncoder> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{PlaintextCount, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let encoder = engine.create_encoder_from(&FloatEncoderMinMaxConfig {
    ///     min: 0.,
    ///     max: 10.,
    ///     nb_bit_precision: 8,
    ///     nb_bit_padding: 1,
    /// })?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&encoder)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(encoder, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<FloatEncoder, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableFloatEncoder {
            version: FloatEncoderVersion,
            inner: ImplFloatEncoder,
        }
        let deserialized: DeserializableFloatEncoder = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableFloatEncoder {
                version: FloatEncoderVersion::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableFloatEncoder {
                version: FloatEncoderVersion::V0,
                inner,
            } => Ok(FloatEncoder(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> FloatEncoder {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`DefaultSerializationEngine`] that
/// operates on 64 bits integers. It deserializes a float encoder array entity.
impl EntityDeserializationEngine<&[u8], FloatEncoderArray> for DefaultSerializationEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{PlaintextCount, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let encoder_array = engine.create_encoder_array_from(&vec![
    ///     FloatEncoderCenterRadiusConfig {
    ///         center: 10.,
    ///         radius: 5.,
    ///         nb_bit_precision: 8,
    ///         nb_bit_padding: 1,
    ///     };
    ///     1
    /// ])?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&encoder_array)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(encoder_array, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<FloatEncoderArray, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableFloatEncoderArray {
            version: FloatEncoderArrayVersion,
            inner: Vec<ImplFloatEncoder>,
        }
        let deserialized: DeserializableFloatEncoderArray = bincode::deserialize(serialized)
            .map_err(DefaultSerializationError::Deserialization)
            .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableFloatEncoderArray {
                version: FloatEncoderArrayVersion::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                DefaultSerializationError::UnsupportedVersion,
            )),
            DeserializableFloatEncoderArray {
                version: FloatEncoderArrayVersion::V0,
                inner,
            } => Ok(FloatEncoderArray(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> FloatEncoderArray {
        self.deserialize(serialized).unwrap()
    }
}
