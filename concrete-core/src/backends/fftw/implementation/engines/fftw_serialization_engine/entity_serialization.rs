#![allow(clippy::missing_safety_doc)]
use crate::backends::fftw::private::crypto::bootstrap::FourierBootstrapKey as ImplFourierBootstrapKey;
use crate::backends::fftw::private::crypto::ggsw::FourierGgswCiphertext as ImplFourierGgswCiphertext;
use crate::backends::fftw::private::crypto::glwe::FourierGlweCiphertext as ImplFourierGlweCiphertext;
use crate::backends::fftw::private::math::fft::Complex64;
use crate::prelude::{
    EntitySerializationEngine, EntitySerializationError, FftwFourierGgswCiphertext32,
    FftwFourierGgswCiphertext32Version, FftwFourierGgswCiphertext64,
    FftwFourierGgswCiphertext64Version, FftwFourierGlweCiphertext32,
    FftwFourierGlweCiphertext32Version, FftwFourierGlweCiphertext64,
    FftwFourierGlweCiphertext64Version, FftwFourierLweBootstrapKey32,
    FftwFourierLweBootstrapKey32Version, FftwFourierLweBootstrapKey64,
    FftwFourierLweBootstrapKey64Version, FftwSerializationEngine, FftwSerializationError,
};
use concrete_fftw::array::AlignedVec;
use serde::Serialize;

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`FftwSerializationEngine`] that operates on
/// 32 bits integers. It serializes a GGSW ciphertext in the Fourier domain.
impl EntitySerializationEngine<FftwFourierGgswCiphertext32, Vec<u8>> for FftwSerializationEngine {
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
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn serialize(
        &mut self,
        entity: &FftwFourierGgswCiphertext32,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableFftwFourierGgswCiphertext32<'a> {
            version: FftwFourierGgswCiphertext32Version,
            inner: &'a ImplFourierGgswCiphertext<AlignedVec<Complex64>, u32>,
        }
        let serializable = SerializableFftwFourierGgswCiphertext32 {
            version: FftwFourierGgswCiphertext32Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(FftwSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &FftwFourierGgswCiphertext32) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`FftwSerializationEngine`] that operates on
/// 64 bits integers. It serializes a GGSW ciphertext in the Fourier domain.
impl EntitySerializationEngine<FftwFourierGgswCiphertext64, Vec<u8>> for FftwSerializationEngine {
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
    fn serialize(
        &mut self,
        entity: &FftwFourierGgswCiphertext64,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableFftwFourierGgswCiphertext64<'a> {
            version: FftwFourierGgswCiphertext64Version,
            inner: &'a ImplFourierGgswCiphertext<AlignedVec<Complex64>, u64>,
        }
        let serializable = SerializableFftwFourierGgswCiphertext64 {
            version: FftwFourierGgswCiphertext64Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(FftwSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &FftwFourierGgswCiphertext64) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`FftwSerializationEngine`] that operates on
/// 32 bits integers. It serializes a GLWE ciphertext in the Fourier domain.
impl EntitySerializationEngine<FftwFourierGlweCiphertext32, Vec<u8>> for FftwSerializationEngine {
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
    fn serialize(
        &mut self,
        entity: &FftwFourierGlweCiphertext32,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableFftwFourierGlweCiphertext32<'a> {
            version: FftwFourierGlweCiphertext32Version,
            inner: &'a ImplFourierGlweCiphertext<AlignedVec<Complex64>, u32>,
        }
        let serializable = SerializableFftwFourierGlweCiphertext32 {
            version: FftwFourierGlweCiphertext32Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(FftwSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &FftwFourierGlweCiphertext32) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`FftwSerializationEngine`] that operates on
/// 64 bits integers. It serializes a GLWE ciphertext in the Fourier domain.
impl EntitySerializationEngine<FftwFourierGlweCiphertext64, Vec<u8>> for FftwSerializationEngine {
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
    fn serialize(
        &mut self,
        entity: &FftwFourierGlweCiphertext64,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableFftwFourierGlweCiphertext64<'a> {
            version: FftwFourierGlweCiphertext64Version,
            inner: &'a ImplFourierGlweCiphertext<AlignedVec<Complex64>, u64>,
        }
        let serializable = SerializableFftwFourierGlweCiphertext64 {
            version: FftwFourierGlweCiphertext64Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(FftwSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &FftwFourierGlweCiphertext64) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`FftwSerializationEngine`] that operates on
/// 32 bits integers. It serializes a LWE bootstrap key in the Fourier domain.
impl EntitySerializationEngine<FftwFourierLweBootstrapKey32, Vec<u8>> for FftwSerializationEngine {
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
    fn serialize(
        &mut self,
        entity: &FftwFourierLweBootstrapKey32,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableFftwFourierLweBootstrapKey32<'a> {
            version: FftwFourierLweBootstrapKey32Version,
            inner: &'a ImplFourierBootstrapKey<AlignedVec<Complex64>, u32>,
        }
        let serializable = SerializableFftwFourierLweBootstrapKey32 {
            version: FftwFourierLweBootstrapKey32Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(FftwSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &FftwFourierLweBootstrapKey32) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}

/// # Description:
/// Implementation of [`EntitySerializationEngine`] for [`FftwSerializationEngine`] that operates on
/// 64 bits integers. It serializes a LWE bootstrap key in the Fourier domain.
impl EntitySerializationEngine<FftwFourierLweBootstrapKey64, Vec<u8>> for FftwSerializationEngine {
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
    fn serialize(
        &mut self,
        entity: &FftwFourierLweBootstrapKey64,
    ) -> Result<Vec<u8>, EntitySerializationError<Self::EngineError>> {
        #[derive(Serialize)]
        struct SerializableFftwFourierLweBootstrapKey64<'a> {
            version: FftwFourierLweBootstrapKey64Version,
            inner: &'a ImplFourierBootstrapKey<AlignedVec<Complex64>, u64>,
        }
        let serializable = SerializableFftwFourierLweBootstrapKey64 {
            version: FftwFourierLweBootstrapKey64Version::V0,
            inner: &entity.0,
        };
        bincode::serialize(&serializable)
            .map_err(FftwSerializationError::Serialization)
            .map_err(EntitySerializationError::Engine)
    }

    unsafe fn serialize_unchecked(&mut self, entity: &FftwFourierLweBootstrapKey64) -> Vec<u8> {
        self.serialize(entity).unwrap()
    }
}
