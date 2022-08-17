#![allow(clippy::missing_safety_doc)]
use crate::backends::fftw::private::crypto::bootstrap::FourierBootstrapKey as ImplFourierBootstrapKey;
use crate::backends::fftw::private::crypto::ggsw::FourierGgswCiphertext as ImplFourierGgswCiphertext;
use crate::backends::fftw::private::crypto::glwe::FourierGlweCiphertext as ImplFourierGlweCiphertext;
use crate::backends::fftw::private::math::fft::Complex64;
use crate::prelude::{
    EntityDeserializationEngine, EntityDeserializationError, FftwFourierGgswCiphertext32,
    FftwFourierGgswCiphertext32Version, FftwFourierGgswCiphertext64,
    FftwFourierGgswCiphertext64Version, FftwFourierGlweCiphertext32,
    FftwFourierGlweCiphertext32Version, FftwFourierGlweCiphertext64,
    FftwFourierGlweCiphertext64Version, FftwFourierLweBootstrapKey32,
    FftwFourierLweBootstrapKey32Version, FftwFourierLweBootstrapKey64,
    FftwFourierLweBootstrapKey64Version, FftwSerializationEngine, FftwSerializationError,
};
use concrete_fftw::array::AlignedVec;
use serde::Deserialize;

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`FftwSerializationEngine`] that operates
/// on 32 bits integers. It deserializes a GGSW ciphertext in the Fourier domain.
impl EntityDeserializationEngine<&[u8], FftwFourierGgswCiphertext32> for FftwSerializationEngine {
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
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(256);
    /// let level = DecompositionLevelCount(1);
    /// let base_log = DecompositionBaseLog(4);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = 3_u32 << 20;
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fftw_engine = FftwEngine::new(())?;
    /// let key: GlweSecretKey32 =
    ///     default_engine.create_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext = default_engine.create_plaintext(&input)?;
    ///
    /// // We encrypt a GGSW ciphertext in the standard domain
    /// let ciphertext =
    ///     default_engine.encrypt_scalar_ggsw_ciphertext(&key, &plaintext, noise, level, base_log)?;
    ///
    /// // Then we convert it to the Fourier domain.
    /// let fourier_ciphertext: FftwFourierGgswCiphertext32 =
    ///     fftw_engine.convert_ggsw_ciphertext(&ciphertext)?;
    ///
    /// let mut serialization_engine = FftwSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&fourier_ciphertext)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(fourier_ciphertext, recovered);

    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<FftwFourierGgswCiphertext32, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableFftwFourierGgswCiphertext32 {
            version: FftwFourierGgswCiphertext32Version,
            inner: ImplFourierGgswCiphertext<AlignedVec<Complex64>, u32>,
        }
        let deserialized: DeserializableFftwFourierGgswCiphertext32 =
            bincode::deserialize(serialized)
                .map_err(FftwSerializationError::Deserialization)
                .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableFftwFourierGgswCiphertext32 {
                version: FftwFourierGgswCiphertext32Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                FftwSerializationError::UnsupportedVersion,
            )),
            DeserializableFftwFourierGgswCiphertext32 {
                version: FftwFourierGgswCiphertext32Version::V0,
                inner,
            } => Ok(FftwFourierGgswCiphertext32(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> FftwFourierGgswCiphertext32 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`FftwSerializationEngine`] that operates
/// on 64 bits integers. It deserializes a GGSW ciphertext in the Fourier domain.
impl EntityDeserializationEngine<&[u8], FftwFourierGgswCiphertext64> for FftwSerializationEngine {
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
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(256);
    /// let level = DecompositionLevelCount(1);
    /// let base_log = DecompositionBaseLog(4);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = 3_u64 << 50;
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fftw_engine = FftwEngine::new(())?;
    /// let key: GlweSecretKey64 =
    ///     default_engine.create_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext = default_engine.create_plaintext(&input)?;
    ///
    /// // We encrypt a GGSW ciphertext in the standard domain
    /// let ciphertext =
    ///     default_engine.encrypt_scalar_ggsw_ciphertext(&key, &plaintext, noise, level, base_log)?;
    ///
    /// // Then we convert it to the Fourier domain.
    /// let fourier_ciphertext: FftwFourierGgswCiphertext64 =
    ///     fftw_engine.convert_ggsw_ciphertext(&ciphertext)?;
    ///
    /// let mut serialization_engine = FftwSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&fourier_ciphertext)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(fourier_ciphertext, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<FftwFourierGgswCiphertext64, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableFftwFourierGgswCiphertext64 {
            version: FftwFourierGgswCiphertext64Version,
            inner: ImplFourierGgswCiphertext<AlignedVec<Complex64>, u64>,
        }
        let deserialized: DeserializableFftwFourierGgswCiphertext64 =
            bincode::deserialize(serialized)
                .map_err(FftwSerializationError::Deserialization)
                .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableFftwFourierGgswCiphertext64 {
                version: FftwFourierGgswCiphertext64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                FftwSerializationError::UnsupportedVersion,
            )),
            DeserializableFftwFourierGgswCiphertext64 {
                version: FftwFourierGgswCiphertext64Version::V0,
                inner,
            } => Ok(FftwFourierGgswCiphertext64(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> FftwFourierGgswCiphertext64 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`FftwSerializationEngine`] that operates
/// on 32 bits integers. It deserializes a GLWE ciphertext in the Fourier domain.
impl EntityDeserializationEngine<&[u8], FftwFourierGlweCiphertext32> for FftwSerializationEngine {
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
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(256);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; 256];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fftw_engine = FftwEngine::new(())?;
    /// let key: GlweSecretKey32 =
    ///     default_engine.create_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_vector = default_engine.create_plaintext_vector(&input)?;
    ///
    /// // We encrypt a GLWE ciphertext in the standard domain
    /// let ciphertext = default_engine.encrypt_glwe_ciphertext(&key, &plaintext_vector, noise)?;
    ///
    /// // Then we convert it to the Fourier domain.
    /// let fourier_ciphertext: FftwFourierGlweCiphertext32 =
    ///     fftw_engine.convert_glwe_ciphertext(&ciphertext)?;
    ///
    /// let mut serialization_engine = FftwSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&fourier_ciphertext)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(fourier_ciphertext, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<FftwFourierGlweCiphertext32, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableFftwFourierGlweCiphertext32 {
            version: FftwFourierGlweCiphertext32Version,
            inner: ImplFourierGlweCiphertext<AlignedVec<Complex64>, u32>,
        }
        let deserialized: DeserializableFftwFourierGlweCiphertext32 =
            bincode::deserialize(serialized)
                .map_err(FftwSerializationError::Deserialization)
                .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableFftwFourierGlweCiphertext32 {
                version: FftwFourierGlweCiphertext32Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                FftwSerializationError::UnsupportedVersion,
            )),
            DeserializableFftwFourierGlweCiphertext32 {
                version: FftwFourierGlweCiphertext32Version::V0,
                inner,
            } => Ok(FftwFourierGlweCiphertext32(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> FftwFourierGlweCiphertext32 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`FftwSerializationEngine`] that operates
/// on 64 bits integers. It deserializes a GLWE ciphertext in the Fourier domain.
impl EntityDeserializationEngine<&[u8], FftwFourierGlweCiphertext64> for FftwSerializationEngine {
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
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(256);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; 256];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fftw_engine = FftwEngine::new(())?;
    /// let key: GlweSecretKey64 =
    ///     default_engine.create_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_vector = default_engine.create_plaintext_vector(&input)?;
    ///
    /// // We encrypt a GLWE ciphertext in the standard domain
    /// let ciphertext = default_engine.encrypt_glwe_ciphertext(&key, &plaintext_vector, noise)?;
    ///
    /// // Then we convert it to the Fourier domain.
    /// let fourier_ciphertext: FftwFourierGlweCiphertext64 =
    ///     fftw_engine.convert_glwe_ciphertext(&ciphertext)?;
    ///
    /// let mut serialization_engine = FftwSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&fourier_ciphertext)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(fourier_ciphertext, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<FftwFourierGlweCiphertext64, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableFftwFourierGlweCiphertext64 {
            version: FftwFourierGlweCiphertext64Version,
            inner: ImplFourierGlweCiphertext<AlignedVec<Complex64>, u64>,
        }
        let deserialized: DeserializableFftwFourierGlweCiphertext64 =
            bincode::deserialize(serialized)
                .map_err(FftwSerializationError::Deserialization)
                .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableFftwFourierGlweCiphertext64 {
                version: FftwFourierGlweCiphertext64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                FftwSerializationError::UnsupportedVersion,
            )),
            DeserializableFftwFourierGlweCiphertext64 {
                version: FftwFourierGlweCiphertext64Version::V0,
                inner,
            } => Ok(FftwFourierGlweCiphertext64(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> FftwFourierGlweCiphertext64 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`FftwSerializationEngine`] that operates
/// on 32 bits integers. It deserializes a LWE bootstrap key in the Fourier domain.
impl EntityDeserializationEngine<&[u8], FftwFourierLweBootstrapKey32> for FftwSerializationEngine {
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
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fftw_engine = FftwEngine::new(())?;
    /// let lwe_sk: LweSecretKey32 = default_engine.create_lwe_secret_key(lwe_dim)?;
    /// let glwe_sk: GlweSecretKey32 = default_engine.create_glwe_secret_key(glwe_dim, poly_size)?;
    /// let bsk: LweBootstrapKey32 =
    ///     default_engine.create_lwe_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise)?;
    ///
    /// let fourier_bsk: FftwFourierLweBootstrapKey32 = fftw_engine.convert_lwe_bootstrap_key(&bsk)?;
    ///
    /// let mut serialization_engine = FftwSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&fourier_bsk)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(fourier_bsk, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<FftwFourierLweBootstrapKey32, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableFftwFourierLweBootstrapKey32 {
            version: FftwFourierLweBootstrapKey32Version,
            inner: ImplFourierBootstrapKey<AlignedVec<Complex64>, u32>,
        }
        let deserialized: DeserializableFftwFourierLweBootstrapKey32 =
            bincode::deserialize(serialized)
                .map_err(FftwSerializationError::Deserialization)
                .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableFftwFourierLweBootstrapKey32 {
                version: FftwFourierLweBootstrapKey32Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                FftwSerializationError::UnsupportedVersion,
            )),
            DeserializableFftwFourierLweBootstrapKey32 {
                version: FftwFourierLweBootstrapKey32Version::V0,
                inner,
            } => Ok(FftwFourierLweBootstrapKey32(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> FftwFourierLweBootstrapKey32 {
        self.deserialize(serialized).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntityDeserializationEngine`] for [`FftwSerializationEngine`] that operates
/// on 64 bits integers. It deserializes a LWE bootstrap key in the Fourier domain.
impl EntityDeserializationEngine<&[u8], FftwFourierLweBootstrapKey64> for FftwSerializationEngine {
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
    /// let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut fftw_engine = FftwEngine::new(())?;
    /// let lwe_sk: LweSecretKey64 = default_engine.create_lwe_secret_key(lwe_dim)?;
    /// let glwe_sk: GlweSecretKey64 = default_engine.create_glwe_secret_key(glwe_dim, poly_size)?;
    /// let bsk: LweBootstrapKey64 =
    ///     default_engine.create_lwe_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise)?;
    ///
    /// let fourier_bsk: FftwFourierLweBootstrapKey64 = fftw_engine.convert_lwe_bootstrap_key(&bsk)?;
    ///
    /// let mut serialization_engine = FftwSerializationEngine::new(())?;
    /// let serialized = serialization_engine.serialize(&fourier_bsk)?;
    /// let recovered = serialization_engine.deserialize(serialized.as_slice())?;
    /// assert_eq!(fourier_bsk, recovered);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn deserialize(
        &mut self,
        serialized: &[u8],
    ) -> Result<FftwFourierLweBootstrapKey64, EntityDeserializationError<Self::EngineError>> {
        #[derive(Deserialize)]
        struct DeserializableFftwFourierLweBootstrapKey64 {
            version: FftwFourierLweBootstrapKey64Version,
            inner: ImplFourierBootstrapKey<AlignedVec<Complex64>, u64>,
        }
        let deserialized: DeserializableFftwFourierLweBootstrapKey64 =
            bincode::deserialize(serialized)
                .map_err(FftwSerializationError::Deserialization)
                .map_err(EntityDeserializationError::Engine)?;
        match deserialized {
            DeserializableFftwFourierLweBootstrapKey64 {
                version: FftwFourierLweBootstrapKey64Version::Unsupported,
                ..
            } => Err(EntityDeserializationError::Engine(
                FftwSerializationError::UnsupportedVersion,
            )),
            DeserializableFftwFourierLweBootstrapKey64 {
                version: FftwFourierLweBootstrapKey64Version::V0,
                inner,
            } => Ok(FftwFourierLweBootstrapKey64(inner)),
        }
    }

    unsafe fn deserialize_unchecked(&mut self, serialized: &[u8]) -> FftwFourierLweBootstrapKey64 {
        self.deserialize(serialized).unwrap()
    }
}
