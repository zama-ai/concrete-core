use concrete_commons::parameters::LweDimension;

use crate::backends::default::implementation::engines::DefaultEngine;
use crate::backends::default::implementation::entities::{LweSecretKey32, LweSecretKey64};
use crate::commons::crypto::secret::LweSecretKey as ImplLweSecretKey;
use crate::specification::engines::{LweSecretKeyCreationEngine, LweSecretKeyCreationError};

/// # Description:
/// Implementation of [`LweSecretKeyCreationEngine`] for [`DefaultEngine`] that operates on
/// 32 bits integers.
impl LweSecretKeyCreationEngine<LweSecretKey32> for DefaultEngine {
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
    /// #
    /// assert_eq!(lwe_secret_key.lwe_dimension(), lwe_dimension);
    /// engine.destroy(lwe_secret_key)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_lwe_secret_key(
        &mut self,
        lwe_dimension: LweDimension,
    ) -> Result<LweSecretKey32, LweSecretKeyCreationError<Self::EngineError>> {
        LweSecretKeyCreationError::perform_generic_checks(lwe_dimension)?;
        Ok(unsafe { self.create_lwe_secret_key_unchecked(lwe_dimension) })
    }

    unsafe fn create_lwe_secret_key_unchecked(
        &mut self,
        lwe_dimension: LweDimension,
    ) -> LweSecretKey32 {
        LweSecretKey32(ImplLweSecretKey::generate_binary(
            lwe_dimension,
            &mut self.secret_generator,
        ))
    }
}

/// # Description:
/// Implementation of [`LweSecretKeyCreationEngine`] for [`DefaultEngine`] that operates on
/// 64 bits integers.
impl LweSecretKeyCreationEngine<LweSecretKey64> for DefaultEngine {
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
    /// #
    /// assert_eq!(lwe_secret_key.lwe_dimension(), lwe_dimension);
    /// engine.destroy(lwe_secret_key)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn create_lwe_secret_key(
        &mut self,
        lwe_dimension: LweDimension,
    ) -> Result<LweSecretKey64, LweSecretKeyCreationError<Self::EngineError>> {
        LweSecretKeyCreationError::perform_generic_checks(lwe_dimension)?;
        Ok(unsafe { self.create_lwe_secret_key_unchecked(lwe_dimension) })
    }

    unsafe fn create_lwe_secret_key_unchecked(
        &mut self,
        lwe_dimension: LweDimension,
    ) -> LweSecretKey64 {
        LweSecretKey64(ImplLweSecretKey::generate_binary(
            lwe_dimension,
            &mut self.secret_generator,
        ))
    }
}
