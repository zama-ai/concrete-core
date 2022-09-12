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
    DefaultSerializationEngine, DefaultSerializationError, EntitySerializationEngine,
    EntitySerializationError, FloatEncoder, FloatEncoderArray, FloatEncoderArrayVersion,
    FloatEncoderVersion, GgswCiphertext32, GgswCiphertext32Version, GgswCiphertext64,
    GgswCiphertext64Version, GgswSeededCiphertext32, GgswSeededCiphertext32Version,
    GgswSeededCiphertext64, GgswSeededCiphertext64Version, GlweCiphertext32,
    GlweCiphertext32Version, GlweCiphertext64, GlweCiphertext64Version, GlweCiphertextArray32,
    GlweCiphertextArray32Version, GlweCiphertextArray64, GlweCiphertextArray64Version,
    GlweCiphertextMutView32, GlweCiphertextMutView64, GlweCiphertextView32, GlweCiphertextView64,
    GlweSecretKey32, GlweSecretKey32Version, GlweSecretKey64, GlweSecretKey64Version,
    GlweSeededCiphertext32, GlweSeededCiphertext32Version, GlweSeededCiphertext64,
    GlweSeededCiphertext64Version, GlweSeededCiphertextArray32, GlweSeededCiphertextArray32Version,
    GlweSeededCiphertextArray64, GlweSeededCiphertextArray64Version, LweBootstrapKey32,
    LweBootstrapKey32Version, LweBootstrapKey64, LweBootstrapKey64Version, LweCiphertext32,
    LweCiphertext32Version, LweCiphertext64, LweCiphertext64Version, LweCiphertextArray32,
    LweCiphertextArray32Version, LweCiphertextArray64, LweCiphertextArray64Version,
    LweCiphertextArrayMutView32, LweCiphertextArrayMutView64, LweCiphertextArrayView32,
    LweCiphertextArrayView64, LweCiphertextMutView32, LweCiphertextMutView64, LweCiphertextView32,
    LweCiphertextView64, LweKeyswitchKey32, LweKeyswitchKey32Version, LweKeyswitchKey64,
    LweKeyswitchKey64Version, LwePackingKeyswitchKey32, LwePackingKeyswitchKey32Version,
    LwePackingKeyswitchKey64, LwePackingKeyswitchKey64Version, LweSecretKey32,
    LweSecretKey32Version, LweSecretKey64, LweSecretKey64Version, LweSeededBootstrapKey32,
    LweSeededBootstrapKey32Version, LweSeededBootstrapKey64, LweSeededBootstrapKey64Version,
    LweSeededCiphertext32, LweSeededCiphertext32Version, LweSeededCiphertext64,
    LweSeededCiphertext64Version, LweSeededCiphertextArray32, LweSeededCiphertextArray32Version,
    LweSeededCiphertextArray64, LweSeededCiphertextArray64Version, LweSeededKeyswitchKey32,
    LweSeededKeyswitchKey32Version, LweSeededKeyswitchKey64, LweSeededKeyswitchKey64Version,
    Plaintext32, Plaintext32Version, Plaintext64, Plaintext64Version, PlaintextArray32,
    PlaintextArray32Version, PlaintextArray64, PlaintextArray64Version,
};
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
    /// let cleartext: Cleartext32 = engine.create_cleartext_from(&input)?;
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&cleartext)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(cleartext, recovered);
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
    /// let cleartext: Cleartext64 = engine.create_cleartext_from(&input)?;
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&cleartext)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(cleartext, recovered);
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
/// on 64 bits integers. It serializes a floating point cleartext.
impl EntitySerializationEngine<CleartextF64, Vec<u8>> for DefaultSerializationEngine {
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
    fn serialize(
        &mut self,
        entity: &CleartextF64,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableCleartextF64<'a> {
            version: CleartextF64Version,
            inner: &'a ImplCleartext<f64>,
        }
        let serializable = SerializableCleartextF64 {
            version: CleartextF64Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &CleartextF64) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 32 bits integers. It serializes a cleartext array entity.
impl EntitySerializationEngine<CleartextArray32, Vec<u8>> for DefaultSerializationEngine {
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
    fn serialize(
        &mut self,
        entity: &CleartextArray32,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableCleartextArray32<'a> {
            version: CleartextArray32Version,
            inner: &'a ImplCleartextList<Vec<u32>>,
        }
        let serializable = SerializableCleartextArray32 {
            version: CleartextArray32Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &CleartextArray32) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 64 bits integers. It serializes a cleartext array entity.
impl EntitySerializationEngine<CleartextArray64, Vec<u8>> for DefaultSerializationEngine {
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
    fn serialize(
        &mut self,
        entity: &CleartextArray64,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableCleartextArray64<'a> {
            version: CleartextArray64Version,
            inner: &'a ImplCleartextList<Vec<u64>>,
        }
        let serializable = SerializableCleartextArray64 {
            version: CleartextArray64Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &CleartextArray64) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 64 bits integers. It serializes a floating point cleartext array entity.
impl EntitySerializationEngine<CleartextArrayF64, Vec<u8>> for DefaultSerializationEngine {
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
    fn serialize(
        &mut self,
        entity: &CleartextArrayF64,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableCleartextArrayF64<'a> {
            version: CleartextArrayF64Version,
            inner: &'a ImplCleartextList<Vec<f64>>,
        }
        let serializable = SerializableCleartextArrayF64 {
            version: CleartextArrayF64Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &CleartextArrayF64) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 32 bits integers. It serializes a GGSW ciphertext entity.
impl EntitySerializationEngine<GgswCiphertext32, Vec<u8>> for DefaultSerializationEngine {
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
/// on 32 bits integers. It serializes a seeded GGSW ciphertext entity.
impl EntitySerializationEngine<GgswSeededCiphertext32, Vec<u8>> for DefaultSerializationEngine {
    /// TODO
    fn serialize(
        &mut self,
        entity: &GgswSeededCiphertext32,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableGgswSeededCiphertext32<'a> {
            version: GgswSeededCiphertext32Version,
            inner: &'a ImplStandardGgswSeededCiphertext<Vec<u32>>,
        }
        let serializable = SerializableGgswSeededCiphertext32 {
            version: GgswSeededCiphertext32Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &GgswSeededCiphertext32) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 64 bits integers. It serializes a seeded GGSW ciphertext entity.
impl EntitySerializationEngine<GgswSeededCiphertext64, Vec<u8>> for DefaultSerializationEngine {
    /// TODO
    fn serialize(
        &mut self,
        entity: &GgswSeededCiphertext64,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableGgswSeededCiphertext64<'a> {
            version: GgswSeededCiphertext64Version,
            inner: &'a ImplStandardGgswSeededCiphertext<Vec<u64>>,
        }
        let serializable = SerializableGgswSeededCiphertext64 {
            version: GgswSeededCiphertext64Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &GgswSeededCiphertext64) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 32 bits integers. It serializes a GLWE ciphertext entity.
impl EntitySerializationEngine<GlweCiphertext32, Vec<u8>> for DefaultSerializationEngine {
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
    /// let raw_buffer = engine.consume_retrieve_glwe_ciphertext(ciphertext)?;
    /// let view: GlweCiphertextView32 =
    ///     engine.create_glwe_ciphertext_from(raw_buffer.as_slice(), polynomial_size)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&view)?;
    /// let recovered: GlweCiphertext32 = serialization_engine.deserialize(serialized.as_slice())?;
    /// let recovered_buffer = engine.consume_retrieve_glwe_ciphertext(recovered)?;
    /// assert_eq!(raw_buffer, recovered_buffer);
    ///
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
    /// let ciphertext = engine.encrypt_glwe_ciphertext(&key, &plaintext_array, noise)?;
    ///
    /// let raw_buffer = engine.consume_retrieve_glwe_ciphertext(ciphertext)?;
    /// let view: GlweCiphertextView64 =
    ///     engine.create_glwe_ciphertext_from(raw_buffer.as_slice(), polynomial_size)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&view)?;
    /// let recovered: GlweCiphertext64 = serialization_engine.deserialize(serialized.as_slice())?;
    /// let recovered_buffer = engine.consume_retrieve_glwe_ciphertext(recovered)?;
    /// assert_eq!(raw_buffer, recovered_buffer);
    ///
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
    /// let mut raw_buffer = engine.consume_retrieve_glwe_ciphertext(ciphertext)?;
    /// let view: GlweCiphertextMutView32 =
    ///     engine.create_glwe_ciphertext_from(raw_buffer.as_mut_slice(), polynomial_size)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&view)?;
    /// let recovered: GlweCiphertext32 = serialization_engine.deserialize(serialized.as_slice())?;
    /// let recovered_buffer = engine.consume_retrieve_glwe_ciphertext(recovered)?;
    /// assert_eq!(raw_buffer, recovered_buffer);
    ///
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
    /// let ciphertext = engine.encrypt_glwe_ciphertext(&key, &plaintext_array, noise)?;
    ///
    /// let mut raw_buffer = engine.consume_retrieve_glwe_ciphertext(ciphertext)?;
    /// let view: GlweCiphertextMutView64 =
    ///     engine.create_glwe_ciphertext_from(raw_buffer.as_mut_slice(), polynomial_size)?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&view)?;
    /// let recovered: GlweCiphertext64 = serialization_engine.deserialize(serialized.as_slice())?;
    /// let recovered_buffer = engine.consume_retrieve_glwe_ciphertext(recovered)?;
    /// assert_eq!(raw_buffer, recovered_buffer);
    ///
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
/// on 32 bits integers. It serializes a GLWE ciphertext array entity.
impl EntitySerializationEngine<GlweCiphertextArray32, Vec<u8>> for DefaultSerializationEngine {
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
    fn serialize(
        &mut self,
        entity: &GlweCiphertextArray32,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableGlweCiphertextArray32<'a> {
            version: GlweCiphertextArray32Version,
            inner: &'a ImplGlweList<Vec<u32>>,
        }
        let serializable = SerializableGlweCiphertextArray32 {
            version: GlweCiphertextArray32Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &GlweCiphertextArray32) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 64 bits integers. It serializes a GLWE ciphertext array entity.
impl EntitySerializationEngine<GlweCiphertextArray64, Vec<u8>> for DefaultSerializationEngine {
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
    fn serialize(
        &mut self,
        entity: &GlweCiphertextArray64,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableGlweCiphertextArray64<'a> {
            version: GlweCiphertextArray64Version,
            inner: &'a ImplGlweList<Vec<u64>>,
        }
        let serializable = SerializableGlweCiphertextArray64 {
            version: GlweCiphertextArray64Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &GlweCiphertextArray64) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 32 bits integers. It serializes a GLWE secret key entity.
impl EntitySerializationEngine<GlweSecretKey32, Vec<u8>> for DefaultSerializationEngine {
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
/// on 32 bits integers. It serializes a seeded GLWE ciphertext entity.
impl EntitySerializationEngine<GlweSeededCiphertext32, Vec<u8>> for DefaultSerializationEngine {
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
    fn serialize(
        &mut self,
        entity: &GlweSeededCiphertext32,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableGlweSeededCiphertext32<'a> {
            version: GlweSeededCiphertext32Version,
            inner: &'a ImplGlweSeededCiphertext<Vec<u32>>,
        }
        let serializable = SerializableGlweSeededCiphertext32 {
            version: GlweSeededCiphertext32Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &GlweSeededCiphertext32) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 64 bits integers. It serializes a seeded GLWE ciphertext entity.
impl EntitySerializationEngine<GlweSeededCiphertext64, Vec<u8>> for DefaultSerializationEngine {
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
    fn serialize(
        &mut self,
        entity: &GlweSeededCiphertext64,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableGlweSeededCiphertext64<'a> {
            version: GlweSeededCiphertext64Version,
            inner: &'a ImplGlweSeededCiphertext<Vec<u64>>,
        }
        let serializable = SerializableGlweSeededCiphertext64 {
            version: GlweSeededCiphertext64Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &GlweSeededCiphertext64) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 32 bits integers. It serializes a seeded GLWE ciphertext array entity.
impl EntitySerializationEngine<GlweSeededCiphertextArray32, Vec<u8>>
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
    fn serialize(
        &mut self,
        entity: &GlweSeededCiphertextArray32,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableGlweSeededCiphertextArray32<'a> {
            version: GlweSeededCiphertextArray32Version,
            inner: &'a ImplGlweSeededList<Vec<u32>>,
        }
        let serializable = SerializableGlweSeededCiphertextArray32 {
            version: GlweSeededCiphertextArray32Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &GlweSeededCiphertextArray32) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 64 bits integers. It serializes a seeded GLWE ciphertext array entity.
impl EntitySerializationEngine<GlweSeededCiphertextArray64, Vec<u8>>
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
    fn serialize(
        &mut self,
        entity: &GlweSeededCiphertextArray64,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableGlweSeededCiphertextArray64<'a> {
            version: GlweSeededCiphertextArray64Version,
            inner: &'a ImplGlweSeededList<Vec<u64>>,
        }
        let serializable = SerializableGlweSeededCiphertextArray64 {
            version: GlweSeededCiphertextArray64Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &GlweSeededCiphertextArray64) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 32 bits integers. It serializes a LWE bootstrap key entity.
impl EntitySerializationEngine<LweBootstrapKey32, Vec<u8>> for DefaultSerializationEngine {
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
    /// let raw_buffer = engine.consume_retrieve_lwe_ciphertext(ciphertext)?;
    /// let view: LweCiphertextView32 = engine.create_lwe_ciphertext_from(raw_buffer.as_slice())?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&view)?;
    /// let recovered: LweCiphertext32 = serialization_engine.deserialize(serialized.as_slice())?;
    /// let recovered_buffer = engine.consume_retrieve_lwe_ciphertext(recovered)?;
    /// assert_eq!(raw_buffer, recovered_buffer);
    ///
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
    /// let raw_buffer = engine.consume_retrieve_lwe_ciphertext(ciphertext)?;
    /// let view: LweCiphertextView64 = engine.create_lwe_ciphertext_from(raw_buffer.as_slice())?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&view)?;
    /// let recovered: LweCiphertext64 = serialization_engine.deserialize(serialized.as_slice())?;
    /// let recovered_buffer = engine.consume_retrieve_lwe_ciphertext(recovered)?;
    /// assert_eq!(raw_buffer, recovered_buffer);
    ///
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
    /// let mut raw_buffer = engine.consume_retrieve_lwe_ciphertext(ciphertext)?;
    /// let view: LweCiphertextMutView32 =
    ///     engine.create_lwe_ciphertext_from(raw_buffer.as_mut_slice())?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&view)?;
    /// let recovered: LweCiphertext32 = serialization_engine.deserialize(serialized.as_slice())?;
    /// let recovered_buffer = engine.consume_retrieve_lwe_ciphertext(recovered)?;
    /// assert_eq!(raw_buffer, recovered_buffer);
    ///
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
    /// let mut raw_buffer = engine.consume_retrieve_lwe_ciphertext(ciphertext)?;
    /// let view: LweCiphertextMutView64 = engine.create_lwe_ciphertext_from(raw_buffer.as_mut_slice())?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&view)?;
    /// let recovered: LweCiphertext64 = serialization_engine.deserialize(serialized.as_slice())?;
    /// let recovered_buffer = engine.consume_retrieve_lwe_ciphertext(recovered)?;
    /// assert_eq!(raw_buffer, recovered_buffer);
    ///
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
/// on 32 bits integers. It serializes a LWE ciphertext array entity.
impl EntitySerializationEngine<LweCiphertextArray32, Vec<u8>> for DefaultSerializationEngine {
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
    fn serialize(
        &mut self,
        entity: &LweCiphertextArray32,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableLweCiphertextArray32<'a> {
            version: LweCiphertextArray32Version,
            inner: &'a ImplLweList<Vec<u32>>,
        }
        let serializable = SerializableLweCiphertextArray32 {
            version: LweCiphertextArray32Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &LweCiphertextArray32) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 64 bits integers. It serializes a LWE ciphertext array entity.
impl EntitySerializationEngine<LweCiphertextArray64, Vec<u8>> for DefaultSerializationEngine {
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
    fn serialize(
        &mut self,
        entity: &LweCiphertextArray64,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableLweCiphertextArray64<'a> {
            version: LweCiphertextArray64Version,
            inner: &'a ImplLweList<Vec<u64>>,
        }
        let serializable = SerializableLweCiphertextArray64 {
            version: LweCiphertextArray64Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &LweCiphertextArray64) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 32 bits integers. It serializes a LWE ciphertext array view entity. Immutable variant.
impl<'b> EntitySerializationEngine<LweCiphertextArrayView32<'b>, Vec<u8>>
    for DefaultSerializationEngine
{
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{LweCiphertextCount, LweDimension, Variance, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    /// let lwe_count = LweCiphertextCount(3);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; lwe_count.0];
    /// let noise = Variance(2_f64.powf(-50.));
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
    /// let raw_buffer = engine.consume_retrieve_lwe_ciphertext_array(ciphertext_array)?;
    /// let view: LweCiphertextArrayView32 = engine
    ///     .create_lwe_ciphertext_array_from(raw_buffer.as_slice(), lwe_dimension.to_lwe_size())?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&view)?;
    /// let recovered: LweCiphertextArray32 =
    ///     serialization_engine.deserialize(serialized.as_slice())?;
    /// let recovered_buffer = engine.consume_retrieve_lwe_ciphertext_array(recovered)?;
    /// assert_eq!(raw_buffer, recovered_buffer);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn serialize(
        &mut self,
        entity: &LweCiphertextArrayView32<'b>,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableLweCiphertextArrayView32<'a, 'b> {
            version: LweCiphertextArray32Version,
            inner: &'a ImplLweList<&'b [u32]>,
        }

        let serializable = SerializableLweCiphertextArrayView32 {
            version: LweCiphertextArray32Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &LweCiphertextArrayView32<'b>) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 64 bits integers. It serializes a LWE ciphertext array view entity. Immutable variant.
impl<'b> EntitySerializationEngine<LweCiphertextArrayView64<'b>, Vec<u8>>
    for DefaultSerializationEngine
{
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{LweCiphertextCount, LweDimension, Variance, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    /// let lwe_count = LweCiphertextCount(3);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; lwe_count.0];
    /// let noise = Variance(2_f64.powf(-50.));
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
    /// let raw_buffer = engine.consume_retrieve_lwe_ciphertext_array(ciphertext_array)?;
    /// let view: LweCiphertextArrayView64 = engine
    ///     .create_lwe_ciphertext_array_from(raw_buffer.as_slice(), lwe_dimension.to_lwe_size())?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&view)?;
    /// let recovered: LweCiphertextArray64 =
    ///     serialization_engine.deserialize(serialized.as_slice())?;
    /// let recovered_buffer = engine.consume_retrieve_lwe_ciphertext_array(recovered)?;
    /// assert_eq!(raw_buffer, recovered_buffer);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn serialize(
        &mut self,
        entity: &LweCiphertextArrayView64<'b>,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableLweCiphertextArrayView64<'a, 'b> {
            version: LweCiphertextArray64Version,
            inner: &'a ImplLweList<&'b [u64]>,
        }

        let serializable = SerializableLweCiphertextArrayView64 {
            version: LweCiphertextArray64Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &LweCiphertextArrayView64<'b>) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 32 bits integers. It serializes a LWE ciphertext array view entity. Mutable variant.
impl<'b> EntitySerializationEngine<LweCiphertextArrayMutView32<'b>, Vec<u8>>
    for DefaultSerializationEngine
{
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{LweCiphertextCount, LweDimension, Variance, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    /// let lwe_count = LweCiphertextCount(3);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; lwe_count.0];
    /// let noise = Variance(2_f64.powf(-50.));
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
    /// let mut raw_buffer = engine.consume_retrieve_lwe_ciphertext_array(ciphertext_array)?;
    /// let view: LweCiphertextArrayMutView32 = engine
    ///     .create_lwe_ciphertext_array_from(raw_buffer.as_mut_slice(), lwe_dimension.to_lwe_size())?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&view)?;
    /// let recovered: LweCiphertextArray32 =
    ///     serialization_engine.deserialize(serialized.as_slice())?;
    /// let recovered_buffer = engine.consume_retrieve_lwe_ciphertext_array(recovered)?;
    /// assert_eq!(raw_buffer, recovered_buffer);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn serialize(
        &mut self,
        entity: &LweCiphertextArrayMutView32<'b>,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableLweCiphertextArrayMutView32<'a, 'b> {
            version: LweCiphertextArray32Version,
            inner: &'a ImplLweList<&'b mut [u32]>,
        }

        let serializable = SerializableLweCiphertextArrayMutView32 {
            version: LweCiphertextArray32Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &LweCiphertextArrayMutView32<'b>) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 64 bits integers. It serializes a LWE ciphertext array view entity. Mutable variant.
impl<'b> EntitySerializationEngine<LweCiphertextArrayMutView64<'b>, Vec<u8>>
    for DefaultSerializationEngine
{
    /// # Example:
    /// ```
    /// use concrete_core::prelude::{LweCiphertextCount, LweDimension, Variance, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    /// let lwe_count = LweCiphertextCount(3);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; lwe_count.0];
    /// let noise = Variance(2_f64.powf(-50.));
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
    /// let mut raw_buffer = engine.consume_retrieve_lwe_ciphertext_array(ciphertext_array)?;
    /// let view: LweCiphertextArrayMutView64 = engine
    ///     .create_lwe_ciphertext_array_from(raw_buffer.as_mut_slice(), lwe_dimension.to_lwe_size())?;
    ///
    /// let mut serialization_engine = DefaultSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&view)?;
    /// let recovered: LweCiphertextArray64 =
    ///     serialization_engine.deserialize(serialized.as_slice())?;
    /// let recovered_buffer = engine.consume_retrieve_lwe_ciphertext_array(recovered)?;
    /// assert_eq!(raw_buffer, recovered_buffer);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn serialize(
        &mut self,
        entity: &LweCiphertextArrayMutView64<'b>,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableLweCiphertextArrayMutView64<'a, 'b> {
            version: LweCiphertextArray64Version,
            inner: &'a ImplLweList<&'b mut [u64]>,
        }

        let serializable = SerializableLweCiphertextArrayMutView64 {
            version: LweCiphertextArray64Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &LweCiphertextArrayMutView64<'b>) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 32 bits integers. It serializes a LWE keyswitch key entity.
impl EntitySerializationEngine<LweKeyswitchKey32, Vec<u8>> for DefaultSerializationEngine {
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
/// on 32 bits integers. It serializes a seeded LWE bootstrap key entity.
impl EntitySerializationEngine<LweSeededBootstrapKey32, Vec<u8>> for DefaultSerializationEngine {
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
    fn serialize(
        &mut self,
        entity: &LweSeededBootstrapKey32,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableLweSeededBootstrapKey32<'a> {
            version: LweSeededBootstrapKey32Version,
            inner: &'a ImplStandardSeededBootstrapKey<Vec<u32>>,
        }
        let serializable = SerializableLweSeededBootstrapKey32 {
            version: LweSeededBootstrapKey32Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &LweSeededBootstrapKey32) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 64 bits integers. It serializes a seeded LWE bootstrap key entity.
impl EntitySerializationEngine<LweSeededBootstrapKey64, Vec<u8>> for DefaultSerializationEngine {
    /// # Example:
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
    fn serialize(
        &mut self,
        entity: &LweSeededBootstrapKey64,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableLweSeededBootstrapKey64<'a> {
            version: LweSeededBootstrapKey64Version,
            inner: &'a ImplStandardSeededBootstrapKey<Vec<u64>>,
        }
        let serializable = SerializableLweSeededBootstrapKey64 {
            version: LweSeededBootstrapKey64Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &LweSeededBootstrapKey64) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 32 bits integers. It serializes a seeded LWE ciphertext entity.
impl EntitySerializationEngine<LweSeededCiphertext32, Vec<u8>> for DefaultSerializationEngine {
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
/// on 32 bits integers. It serializes a seeded LWE ciphertext array entity.
impl EntitySerializationEngine<LweSeededCiphertextArray32, Vec<u8>> for DefaultSerializationEngine {
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
    fn serialize(
        &mut self,
        entity: &LweSeededCiphertextArray32,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableLweSeededCiphertextArray32<'a> {
            version: LweSeededCiphertextArray32Version,
            inner: &'a ImplLweSeededList<Vec<u32>>,
        }
        let serializable = SerializableLweSeededCiphertextArray32 {
            version: LweSeededCiphertextArray32Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &LweSeededCiphertextArray32) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 64 bits integers. It serializes a seeded LWE ciphertext array entity.
impl EntitySerializationEngine<LweSeededCiphertextArray64, Vec<u8>> for DefaultSerializationEngine {
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
    fn serialize(
        &mut self,
        entity: &LweSeededCiphertextArray64,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableLweSeededCiphertextArray64<'a> {
            version: LweSeededCiphertextArray64Version,
            inner: &'a ImplLweSeededList<Vec<u64>>,
        }
        let serializable = SerializableLweSeededCiphertextArray64 {
            version: LweSeededCiphertextArray64Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &LweSeededCiphertextArray64) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 32 bits integers. It serializes a seeded LWE keyswitch key entity.
impl EntitySerializationEngine<LweSeededKeyswitchKey32, Vec<u8>> for DefaultSerializationEngine {
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
    fn serialize(
        &mut self,
        entity: &LweSeededKeyswitchKey32,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct LweSeededKeyswitchKey32<'a> {
            version: LweSeededKeyswitchKey32Version,
            inner: &'a ImplLweSeededKeyswitchKey<Vec<u32>>,
        }
        let serializable = LweSeededKeyswitchKey32 {
            version: LweSeededKeyswitchKey32Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &LweSeededKeyswitchKey32) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 64 bits integers. It serializes a seeded LWE keyswitch key entity.
impl EntitySerializationEngine<LweSeededKeyswitchKey64, Vec<u8>> for DefaultSerializationEngine {
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
    fn serialize(
        &mut self,
        entity: &LweSeededKeyswitchKey64,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct LweSeededKeyswitchKey64<'a> {
            version: LweSeededKeyswitchKey64Version,
            inner: &'a ImplLweSeededKeyswitchKey<Vec<u64>>,
        }
        let serializable = LweSeededKeyswitchKey64 {
            version: LweSeededKeyswitchKey64Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &LweSeededKeyswitchKey64) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 32 bits integers. It serializes a packing keyswitch key entity.
impl EntitySerializationEngine<LwePackingKeyswitchKey32, Vec<u8>> for DefaultSerializationEngine {
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
    fn serialize(
        &mut self,
        entity: &LwePackingKeyswitchKey32,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializablePackingKeyswitchKey32<'a> {
            version: LwePackingKeyswitchKey32Version,
            inner: &'a ImplLwePackingKeyswitchKey<Vec<u32>>,
        }
        let serializable = SerializablePackingKeyswitchKey32 {
            version: LwePackingKeyswitchKey32Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &LwePackingKeyswitchKey32) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 64 bits integers. It serializes a packing keyswitch key entity.
impl EntitySerializationEngine<LwePackingKeyswitchKey64, Vec<u8>> for DefaultSerializationEngine {
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
    fn serialize(
        &mut self,
        entity: &LwePackingKeyswitchKey64,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializablePackingKeyswitchKey64<'a> {
            version: LwePackingKeyswitchKey64Version,
            inner: &'a ImplLwePackingKeyswitchKey<Vec<u64>>,
        }
        let serializable = SerializablePackingKeyswitchKey64 {
            version: LwePackingKeyswitchKey64Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &LwePackingKeyswitchKey64) -> Vec<u8> {
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
/// on 32 bits integers. It serializes a plaintext array entity.
impl EntitySerializationEngine<PlaintextArray32, Vec<u8>> for DefaultSerializationEngine {
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
    fn serialize(
        &mut self,
        entity: &PlaintextArray32,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializablePlaintextArray32<'a> {
            version: PlaintextArray32Version,
            inner: &'a ImplPlaintextList<Vec<u32>>,
        }
        let serializable = SerializablePlaintextArray32 {
            version: PlaintextArray32Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &PlaintextArray32) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 64 bits integers. It serializes a plaintext array entity.
impl EntitySerializationEngine<PlaintextArray64, Vec<u8>> for DefaultSerializationEngine {
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
    fn serialize(
        &mut self,
        entity: &PlaintextArray64,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializablePlaintextArray64<'a> {
            version: PlaintextArray64Version,
            inner: &'a ImplPlaintextList<Vec<u64>>,
        }
        let serializable = SerializablePlaintextArray64 {
            version: PlaintextArray64Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &PlaintextArray64) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 64 bits integers. It serializes a float encoder entity.
impl EntitySerializationEngine<FloatEncoder, Vec<u8>> for DefaultSerializationEngine {
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
    fn serialize(
        &mut self,
        entity: &FloatEncoder,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableFloatEncoder<'a> {
            version: FloatEncoderVersion,
            inner: &'a ImplFloatEncoder,
        }
        let serializable = SerializableFloatEncoder {
            version: FloatEncoderVersion::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &FloatEncoder) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`DefaultSerializationEngine`] that operates
/// on 64 bits integers. It serializes a float encoder array entity.
impl EntitySerializationEngine<FloatEncoderArray, Vec<u8>> for DefaultSerializationEngine {
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
    fn serialize(
        &mut self,
        entity: &FloatEncoderArray,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableFloatEncoderArray<'a> {
            version: FloatEncoderArrayVersion,
            inner: &'a Vec<ImplFloatEncoder>,
        }
        let serializable = SerializableFloatEncoderArray {
            version: FloatEncoderArrayVersion::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(DefaultSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &FloatEncoderArray) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}
